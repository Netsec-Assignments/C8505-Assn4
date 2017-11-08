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

from scapy.all import *
from twisted.internet import *
from twisted.internet.interfaces import *
from netfilterqueue import NetfilterQueue

class QueuedReadDescriptor(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(nfQueueCallback)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'
