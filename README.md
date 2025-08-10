Basic version:  
Start the Ryu controller:  
ryu-manager controller.py

Start the Flask user authentication service:  
sudo python3 controller2.py

Start the Mininet base topology:
sudo python3 topo.py

MAC Authentication (enter in a new terminal):  
The curl -x POST http://127.0.0.1:5000/auth_mac \
-H "Content-Type: application/json" \
-d '{"mac": "00:00:00:00:00:01"}'

The mac address is obtained from the command line window of topo through h1 ifconfig

Advanced Version:  
Start the Ryu controller:  
ryu-manager user_controller.py

Start the Flask user authentication service:  
sudo python3 user.py

Start the Mininet base topology:  
sudo python3 topo.py

User authentication (can be ping after authentication):  
curl -X POST http://localhost:5000/auth_user \  
-H "Content-Type: application/json" \  
-d '{"username": "1", "password": "1", "mac": "00:00:00:00:00:01"}'

The mac address is obtained from the command line window of topo through h1 ifconfig

Blacklist (even after authentication, communication is not possible):  
curl -X POST http://localhost:5000/blacklist \  
-H "Content-Type: application/json" \  
-d '{"mac": "00:00:00:00:00:01"}'

View the current blacklist:  
curl http://localhost:5000/blacklist  

Remove from the blacklist:  
curl -X DELETE http://localhost:5000/blacklist \  
-H "Content-Type: application/json" \  
-d '{"mac": "00:00:00:00:00:01"}'
