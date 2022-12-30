import psycopg
from turbo_sticks.config import db_pool


def main() -> None:
    # flush old sessions
    with psycopg.connect(db_pool.uri) as conn:
        with conn.cursor() as cur:
            sql = """
                    DELETE
                      FROM sessions
                     WHERE session_expires_on < current_timestamp"""
            cur.execute(sql)


if __name__ == '__main__':
    main()
