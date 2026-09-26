import slapdtest


class TestSlapdObject:
    def test_context_manager(self):
        with slapdtest.SlapdObject() as server:
            assert server._proc is not None
        assert server._proc is None

    def test_context_manager_after_start(self):
        server = slapdtest.SlapdObject()
        server.start()
        assert server._proc is not None
        with server:
            assert server._proc is not None
        assert server._proc is None
