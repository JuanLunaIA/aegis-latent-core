---
name: test-author
tier: MEDIUM
domains: [pytest, unit, integration, e2e, property-based, hypothesis, load-testing]
---
## Activation
Load on: "write tests for X", "complete coverage", "test e2e flow Y", "property tests".

## Test Hierarchy (apply all levels)
```
Unit tests          Pure functions, isolated logic, no I/O. Fast (< 1ms each).
Integration tests   Service + real DB/cache (testcontainers). Medium (< 1s each).
E2E tests           Critical user journeys via API. Slow (< 30s each). Few in number.
Property-based      Invariant testing with hypothesis. Runs many inputs automatically.
Load tests          Locust/k6. SLO validation under expected + 3× peak traffic.
Security tests      Injection payloads, auth bypass attempts, boundary violations.
```

## Test Structure
```python
# AAA pattern — labeled with comments
def test_create_order_with_valid_payload(db_session: AsyncSession) -> None:
    # Arrange
    user = UserFactory.create(plan="pro")
    payload = OrderCreate(items=[{"sku": "SKU-001", "qty": 2}])

    # Act
    result = await order_service.create(payload, owner=user, session=db_session)

    # Assert
    assert result.id is not None
    assert result.status == OrderStatus.PENDING
    assert result.total_cents == 2000
    # Verify side effects
    assert await db_session.get(OrderEvent, {"order_id": result.id}) is not None
```

## Coverage Requirements
```
Critical paths (auth, payments, data mutation):  100% branch coverage
Business logic:                                   90%+ branch coverage
I/O adapters (DB, HTTP, queue):                  70%+ (integration-tested)
Glue code:                                        50%+ (no logic to test)

Never mock: business logic, pure functions, domain rules
Always mock: external HTTP, time.time(), email/SMS sending, payment processors
Use testcontainers: real DB for integration tests (not SQLite-as-substitute)
```

## Property-Based Testing
```python
from hypothesis import given, settings, strategies as st

@given(
    amount=st.integers(min_value=1, max_value=10_000_00),  # 1 cent to $100k
    currency=st.sampled_from(["USD", "EUR", "GBP"]),
)
@settings(max_examples=500)
def test_money_addition_is_commutative(amount: int, currency: str) -> None:
    a = Money(amount, currency)
    b = Money(amount, currency)
    assert a + b == b + a  # invariant: commutativity

@given(st.text(min_size=0, max_size=10_000))
def test_sanitizer_never_raises(raw_input: str) -> None:
    # Property: sanitizer handles any input without exception
    result = sanitize_html(raw_input)
    assert isinstance(result, str)
```

## Fixture Patterns
```python
# conftest.py — shared fixtures
@pytest.fixture(scope="session")
async def db_engine() -> AsyncGenerator[AsyncEngine, None]:
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest.fixture(autouse=True)  # clean state per test
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(db_engine) as session:
        await session.begin()
        yield session
        await session.rollback()  # no test data persists
```
