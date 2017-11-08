#/*********************************************************************************************
#       Name:	reader.py
#
#       Developer:	Mat Siwoski/Shane Spoor
#
#       Created On: 2017-10-24
#
#       Description:
#       Class to handle the read descriptor from the Twisted Interface.
#
#
#    Revisions:
#    (none)
#
###################################################################################################


#!/usr/bin/env python3
import netfilterqueue

class Reader(object):
    def __init__(self, pktCallback, exitCallback):
        self.q = netfilterqueue.NetfilterQueue()
        self.pktCallback = pktCallback
        self.exitCallback = exitCallback

    def run(self):
        self.q.bind(0, self.pktCallback, max_len=5000, mode=netfilterqueue.COPY_PACKET)

        try:
            self.run()
        except KeyboardInterrupt:
            self.q.unbind()
            self.exitCallback()
            
