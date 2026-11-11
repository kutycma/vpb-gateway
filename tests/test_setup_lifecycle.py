import asyncio
from tests.test_gateway import service

async def test_unregistered_service_does_not_contact_bank(service):
    async def forbidden(): raise AssertionError('Must not contact bank before registration')
    service.bank.fetch_history=forbidden
    async with service.lifespan(None):
        await asyncio.sleep(.01)
        assert service.fetcher.last_fetch_ok_at is None
