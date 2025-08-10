# File: auth_controller.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

authenticated_hosts = set()
datapaths = {}
WIFI_AUTH_INSTANCE_NAME = 'wifi_auth_api'

class AuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(AuthController, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, {WIFI_AUTH_INSTANCE_NAME: self})
        print("Controller started.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        print("Default flow installed.")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src_mac = eth.src

        self.logger.info("PACKET_IN from MAC: %s at port: %s", src_mac, in_port)

        if src_mac in authenticated_hosts:
            self.logger.info("Authorized MAC: %s", src_mac)
            return

        match = parser.OFPMatch(eth_src=src_mac)
        actions = [parser.OFPActionOutput(3)]  # Redirect to auth server
        self.add_flow(datapath, 10, match, actions, idle_timeout=300)

        self.logger.info("Unauthorized MAC %s redirected to auth server", src_mac)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def authorize_mac(self, mac):
        authenticated_hosts.add(mac)
        for dp in datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            for direction in ['eth_src', 'eth_dst']:
                match = parser.OFPMatch(**{direction: mac})
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=dp,
                                        priority=50,
                                        match=match,
                                        instructions=inst,
                                        idle_timeout=300)
                dp.send_msg(mod)
        self.logger.info("MAC %s authorized with bidirectional flow.", mac)
        return True


class RestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.auth_app = data[WIFI_AUTH_INSTANCE_NAME]

    @route('permit', '/permit', methods=['POST'])
    def permit(self, req, **kwargs):
        try:
            content = req.body.decode('utf-8')
            data = json.loads(content)
            mac = data.get('mac')
            if not mac:
                return Response(status=400, body="Missing MAC address.")
            self.auth_app.authorize_mac(mac)
            return Response(status=200, body=f"MAC {mac} authorized.")
        except Exception as e:
            return Response(status=500, body=str(e))
