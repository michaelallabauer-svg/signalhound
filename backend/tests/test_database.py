from sqlalchemy import create_engine, text


def test_database_connectivity_with_sqlalchemy() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1")).scalar_one()

    assert result == 1

