from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket


class WS_Collector(WebSocket):

    def handleMessage(self):
        # echo message back to client
        # self.sendMessage(self.data)
        print self.data

    def handleConnected(self):
        # print(self.address, 'connected')
        pass

    def handleClose(self):
        print(self.address, 'closed')
        pass


server = SimpleWebSocketServer('', 8000, WS_Collector)
server.serveforever()
