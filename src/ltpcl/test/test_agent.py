import unittest
from udpcl import agent


class TestConversation(unittest.TestCase):

    def test_eq(self):
        conv_empty = agent.Conversation()
        self.assertEqual(conv_empty, agent.Conversation())

    def test_dict_key(self):
        ctr = {}
        self.assertNotIn(agent.Conversation().key, ctr)

        ctr[agent.Conversation(peer_port=80).key] = 'hi'
        self.assertNotIn(agent.Conversation().key, ctr)
        self.assertEqual(agent.Conversation().find_in(ctr), 'hi')
