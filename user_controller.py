from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

authenticated_hosts = set()
blacklist = set()
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

        if src_mac in blacklist:
            self.logger.info("Blocked MAC %s is in blacklist. Dropping packet.", src_mac)
            match = parser.OFPMatch(eth_src=src_mac)
            actions = []
            self.add_flow(datapath, 100, match, actions, idle_timeout=0, hard_timeout=0)
            return

        if src_mac in authenticated_hosts:
            self.logger.info("Authorized MAC: %s", src_mac)
            return

        match = parser.OFPMatch(eth_src=src_mac)
        actions = [parser.OFPActionOutput(3)]  # auth server port
        self.add_flow(datapath, 10, match, actions, idle_timeout=300)

        self.logger.info("Unauthorized MAC %s redirected to auth server.", src_mac)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def authorize_mac(self, mac):
        if mac in blacklist:
            self.logger.info("MAC %s is in blacklist. Authorization denied.", mac)
            return False

        authenticated_hosts.add(mac)

        for dp in datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            # 删除之前可能存在的 drop 流表
            match = parser.OFPMatch(eth_src=mac)
            mod = parser.OFPFlowMod(
                datapath=dp,
                match=match,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY
            )
            dp.send_msg(mod)

            # 添加允许双向流表
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

    def add_blacklist(self, mac):
        blacklist.add(mac)
        self.logger.info("MAC %s added to blacklist.", mac)

    def remove_blacklist(self, mac):
        if mac in blacklist:
            blacklist.remove(mac)
            self.logger.info("MAC %s removed from blacklist.", mac)


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
            success = self.auth_app.authorize_mac(mac)
            if success:
                return Response(status=200, body=f"MAC {mac} authorized.")
            else:
                return Response(status=403, body=f"MAC {mac} is blacklisted.")
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('blacklist_add', '/blacklist', methods=['POST'])
    def add_blacklist(self, req, **kwargs):
        try:
            content = req.body.decode('utf-8')
            data = json.loads(content)
            mac = data.get('mac')
            if not mac:
                return Response(status=400, body="Missing MAC address.")
            self.auth_app.add_blacklist(mac)
            return Response(status=200, body=json.dumps({"message": f"MAC {mac} added to blacklist"}))
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('blacklist_remove', '/blacklist', methods=['DELETE'])
    def remove_blacklist(self, req, **kwargs):
        try:
            content = req.body.decode('utf-8')
            data = json.loads(content)
            mac = data.get('mac')
            if not mac:
                return Response(status=400, body="Missing MAC address.")

            if mac in blacklist:
                self.auth_app.remove_blacklist(mac)
                self.auth_app.authorize_mac(mac)  # 移除黑名单后自动授权
                return Response(status=200, body=json.dumps({"message": f"MAC {mac} removed from blacklist and unblocked"}))
            else:
                return Response(status=404, body=json.dumps({"message": f"MAC {mac} not found in blacklist"}))
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('deny', '/deny', methods=['POST'])
    def deny(self, req, **kwargs):
        try:
            content = req.body.decode('utf-8')
            data = json.loads(content)
            mac = data.get('mac')
            if not mac:
                return Response(status=400, body="Missing MAC address.")

            for dp in datapaths.values():
                parser = dp.ofproto_parser
                ofproto = dp.ofproto

                match = parser.OFPMatch(eth_src=mac)
                actions = []
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=dp,
                                        priority=100,
                                        match=match,
                                        instructions=inst,
                                        idle_timeout=0,
                                        hard_timeout=0)
                dp.send_msg(mod)

            return Response(status=200, body=f"MAC {mac} blocked.")
        except Exception as e:
            return Response(status=500, body=str(e))
