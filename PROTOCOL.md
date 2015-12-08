Protocols
----------------------------------------

### Ping Protocol
Wifidog uses the ping protocol as a heartbeat mechanism to send current status information to the auth server. This enables central logging of the status for each node at the auth server.
The wifidog client uses a setting in the conf file to periodically start a thread ( ping_thread.c ) to send a status message via http to the auth server. The message format is
```
http://auth_sever/ping/?
gw_id=%s
sys_uptime=%lu
sys_memfree=%u
sys_load=%.2f
wifidog_uptime=%lu
```

A typical HTTP request would be:

```
GET /ping/?gw_id=001217DA42D2&sys_uptime=742725&sys_memfree=2604&sys_load=0.03&wifidog_uptime=3861 HTTP/1.0
User-Agent: WiFiDog 1.1.3_beta6
Host: auth.ilesansfil.org
```
To this the auth server is expected to respond with an http message containing the word "Pong".

### Auth Protocol

The gateway will contact the auth server everytime a user needs validation. And periodically the gateway will report the status of each user connection to the auth server. this is used to reporting incoming/outgoing counters for each user, to show that the user is still connected, and to allow the auth server to trigger disconnects of users the should no longer have access.

The following message is sent for each connected user
```
auth_server:/auth/index.php?
stage=
ip=
mac=
token=
incoming=
outgoing=

stage = counters or login, depending if this is a new client or not.
```

The format of the response should be:
`Auth: <number from user status list>`

The new user status can be:
```
0 - AUTH_DENIED - User firewall users are deleted and the user removed.
6 - AUTH_VALIDATION_FAILED - User email validation timeout has occured and user/firewall is deleted
1 - AUTH_ALLOWED - User was valid, add firewall rules if not present
5 - AUTH_VALIDATION - Permit user access to email to get validation email under default rules
-1 - AUTH_ERROR - An error occurred during the validation process
```

Typical URLs would be:
```
GET /auth/?stage=counters&ip=7.0.0.107&mac=00:40:05:5F:44:43&token=4f473ae3ddc5c1c2165f7a0973c57a98&incoming=6031353&outgoing=827770 HTTP/1.0
User-Agent: WiFiDog 1.1.3_beta6
Host: auth.ilesansfil.org
```

### Login Protocol

Upon initial HTTP request, the client will be redirected to the following URL by the gateway:
`login/?gw_address=%s&gw_port=%d&gw_id=%s&url=%s`

Upon successfull login, the client will be redirected to the gateway:
`http://" . $gw_address . ":" . $gw_port . "/wifidog/auth?token=" . $token`

Then, the gateway use Auth protocol to validate the token with auth server.
