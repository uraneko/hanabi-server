// use sqlx::Acquire;
use sqlx::{Result, Row, SqliteConnection, sqlite::SqliteRow};

pub async fn register_user(
    conn: &mut SqliteConnection,
    name: &str,
    email: Option<&[u8]>,
    pswd: &[u8],
    salt: &str,
    created: i64,
) -> Result<()> {
    sqlx::query("insert into users (name, email, pswd, salt, created) values ($1, $2, $3, $4, $5)")
        .bind(name)
        .bind(email)
        .bind(pswd)
        .bind(salt)
        .bind(created)
        .execute(conn)
        .await?
        .rows_affected();

    Ok(())
}

pub async fn get_user_by_name(conn: &mut SqliteConnection, name: &str) -> Result<Vec<SqliteRow>> {
    sqlx::query("select * from users where name = $1")
        .bind(name)
        .fetch_all(conn)
        .await
}

pub async fn get_name_by_refresh(
    conn: &mut SqliteConnection,
    refresh: &[u8],
) -> Result<Vec<SqliteRow>> {
    sqlx::query("select name from tokens where refresh = $1")
        .bind(refresh)
        .fetch_all(conn)
        .await
}

pub async fn get_user_by_email(
    conn: &mut SqliteConnection,
    email: &[u8],
) -> Result<Vec<SqliteRow>> {
    sqlx::query("select * from users where email = $1")
        .bind(email)
        .fetch_all(conn)
        .await
}

async fn check_no_refresh(conn: &mut SqliteConnection, name: &str, token: &[u8]) -> Result<()> {
    let Ok(empty) = sqlx::query("select * from tokens where name = $1 and refresh = $2")
        .bind(name)
        .bind(token)
        .fetch_all(&mut *conn)
        .await
    else {
        return Err(sqlx::Error::Io(std::io::Error::other(
            "expected query to return Ok",
        )));
    };
    if !empty.is_empty() {
        return Err(sqlx::Error::Io(std::io::Error::other(
            "expected query result to be empty",
        )));
    }

    Ok(())
}

pub async fn db_write_login_refresh(
    conn: &mut SqliteConnection,
    name: &str,
    refresh: &[u8],
) -> Result<()> {
    check_no_refresh(&mut *conn, name, refresh).await?;

    sqlx::query("insert into tokens (name, refresh) values ($1, $2)")
        .bind(name)
        .bind(refresh)
        .execute(conn)
        .await?
        .rows_affected();

    Ok(())
}

pub async fn db_clear_login_refresh(conn: &mut SqliteConnection, refresh: &[u8]) -> Result<()> {
    sqlx::query("delete from tokens where refresh = $1")
        .bind(refresh)
        .execute(conn)
        .await?
        .rows_affected();

    Ok(())
}

pub async fn db_query_field_availability(
    conn: &mut SqliteConnection,
    mut name: &str,
    value: &str,
) -> Result<Vec<SqliteRow>> {
    if name.starts_with("user_") {
        name = &name[5..];
    }

    sqlx::query(&["select * from users where ", name, " = $1;"].concat())
        .bind(value)
        .fetch_all(conn)
        .await
}

async fn check_access(conn: &mut SqliteConnection, name: &str, token: &[u8]) -> Result<usize> {
    let Ok(rows) = sqlx::query("select * from tokens where name = $1")
        .bind(name)
        .bind(token)
        .fetch_all(&mut *conn)
        .await
    else {
        return Err(sqlx::Error::Io(std::io::Error::other(
            "expected query to return Ok",
        )));
    };

    match rows.len() {
        0 => return Ok(0),
        1 => {
            if rows[0]
                .try_get::<Option<Vec<u8>>, &str>("access")
                .map_err(|_| {
                    sqlx::Error::Io(std::io::Error::other(
                        "expected expected no rows or one row, duplicate names are not allowed",
                    ))
                })?
                .is_some()
            {
                return Err(sqlx::Error::Io(std::io::Error::other(
                    "expected expected no rows or one row, duplicate names are not allowed",
                )));
            }

            return Ok(1);
        }
        _ => {
            return Err(sqlx::Error::Io(std::io::Error::other(
                "expected expected no rows or one row, duplicate names are not allowed",
            )));
        }
    }
}

pub async fn db_cache_login_access(
    conn: &mut SqliteConnection,
    name: &str,
    access: &[u8],
) -> Result<()> {
    let size = check_access(&mut *conn, name, access).await?;
    match size {
        0 => sqlx::query("insert into tokens (name, access) values ($1, $2)")
            .bind(name)
            .bind(access)
            .execute(conn)
            .await?
            .rows_affected(),
        1 => sqlx::query("update tokens set access = $1 where name = $2")
            .bind(access)
            .bind(name)
            .execute(conn)
            .await?
            .rows_affected(),
        _ => {
            unreachable!("the value being matched came from a fun that only returns Ok(0|1) | Err")
        }
    };

    Ok(())
}

pub async fn db_clear_login_access(
    conn: &mut SqliteConnection,
    name: &str,
    access: &[u8],
) -> Result<()> {
    sqlx::query("delete from tokens where name = $1 and access = $2")
        .bind(name)
        .bind(access)
        .execute(conn)
        .await?
        .rows_affected();

    Ok(())
}

pub async fn db_clear_login_access_nameless(
    conn: &mut SqliteConnection,
    access: &[u8],
) -> Result<()> {
    sqlx::query("delete from tokens where access = $1")
        .bind(access)
        .execute(conn)
        .await?
        .rows_affected();

    Ok(())
}
