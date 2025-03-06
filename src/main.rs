use actix_web::{
    get, post, web, App, Error, HttpResponse, HttpServer,
    HttpRequest,
};
use chrono::{Utc, DateTime};
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, env};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};

#[derive(Debug, Serialize, Deserialize)]
struct IngestData {
    sensor_name: String,
    field: String,
    value: String,
    #[serde(rename = "type")]
    data_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SensorData {
    timestamp: String,
    sensor_name: String,
    field: String,
    value: String,
    #[serde(rename = "type")]
    data_type: String,
}

struct AppState {
    db: Mutex<Connection>,
}

async fn insert_sensor_data(
    state: &web::Data<AppState>,
    data: &IngestData,
) -> Result<(), rusqlite::Error> {
    let now: DateTime<Utc> = Utc::now();
    let now_truncated = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let conn = state.db.lock().unwrap();
    conn.execute(
        "INSERT INTO sensor_data (timestamp, sensor_name, field, value, type) VALUES (?, ?, ?, ?, ?)",
        params![&now_truncated, &data.sensor_name, &data.field, &data.value, &data.data_type],
    )?;
    Ok(())
}

fn verify_signature(signature: &str, body: &str) -> bool {
    // TODO: Replace with actual RSA public key
    let public_key = "test_public_key";

    // Create a SHA256 HMAC with the public key
    let mut mac = Hmac::<Sha256>::new_from_slice(public_key.as_bytes())
        .expect("HMAC can take key of any size");

    mac.update(body.as_bytes());

    // Finalize and get the result as a MAC code
    let result = mac.finalize().into_bytes();

    // Base64 encode the HMAC result
    let expected_signature = BASE64_STANDARD.encode(result);

    // Compare the expected signature with the provided signature
    signature == expected_signature
}


#[post("/ingest")]
async fn ingest_data(
    req: HttpRequest,
    data: web::Json<IngestData>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    // Extract the signature from the X-Signature header
    let signature = match req.headers().get("X-Signature") {
        Some(header) => header.to_str().unwrap_or(""),
        None => return Ok(HttpResponse::BadRequest().body("X-Signature header missing")),
    };

    // Serialize the body to a string
    let body = serde_json::to_string(&data).unwrap_or_else(|_| "".to_string());

    // Verify the signature
    if !verify_signature(signature, &body) {
        return Ok(HttpResponse::Unauthorized().body("Invalid signature"));
    }

    let ingest_data = data.into_inner();
    insert_sensor_data(&state, &ingest_data)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().body("Data ingested"))
}

async fn query_sensor_data(
    state: &web::Data<AppState>,
    sensor_name: &str,
    field: Option<&str>,
) -> Result<Vec<SensorData>, rusqlite::Error> {
    let conn = state.db.lock().unwrap();

    let sql = match field {
        Some(_field) => {
            "SELECT timestamp, sensor_name, field, value, type FROM sensor_data WHERE sensor_name = ? AND field = ? ORDER BY timestamp DESC".to_string()
        }
        None => {
            "SELECT timestamp, sensor_name, field, value, type FROM sensor_data WHERE sensor_name = ? ORDER BY timestamp DESC".to_string()
        }
    };

    let mut stmt = conn.prepare(&sql)?;

    let result: Result<Vec<SensorData>, rusqlite::Error> = match field {
        Some(field) => {
            let mut rows = stmt.query_map(params![sensor_name, field], |row| {
                Ok(SensorData {
                    timestamp: row.get(0)?,
                    sensor_name: row.get(1)?,
                    field: row.get(2)?,
                    value: row.get(3)?,
                    data_type: row.get(4)?,
                })
            })?;
            let mut result = Vec::new();
            while let Some(row) = rows.next().transpose()? {
                result.push(row);
            }
            Ok(result)
        }
        None => {
            let mut rows = stmt.query_map(params![sensor_name], |row| {
                Ok(SensorData {
                    timestamp: row.get(0)?,
                    sensor_name: row.get(1)?,
                    field: row.get(2)?,
                    value: row.get(3)?,
                    data_type: row.get(4)?,
                })
            })?;
            let mut result = Vec::new();
            while let Some(row) = rows.next().transpose()? {
                result.push(row);
            }
            Ok(result)
        }
    };

    result
}


#[get("/data/{sensor_name}")]
async fn get_sensor_data(
    sensor_name: web::Path<String>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let sensor_name = sensor_name.into_inner();
    let data = query_sensor_data(&state, &sensor_name, None)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if data.is_empty() {
        return Ok(HttpResponse::NotFound().body("Sensor data not found"));
    }

    Ok(HttpResponse::Ok().json(data))
}

#[get("/data/{sensor_name}/{field}")]
async fn get_sensor_data_by_field(
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let (sensor_name, field) = path.into_inner();
    let data = query_sensor_data(&state, &sensor_name, Some(&field))
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

   if data.is_empty() {
        return Ok(HttpResponse::NotFound().body("Sensor data not found"));
    }

    Ok(HttpResponse::Ok().json(data))
}


async fn create_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sensor_data (
            timestamp TEXT NOT NULL,
            sensor_name TEXT NOT NULL,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            type TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db_path = env::var("DATABASE_URL").unwrap_or_else(|_| "data.db".to_string());

    println!("Using database: {}", db_path);

    let conn = Connection::open(&db_path).expect("Failed to open database");
    create_table(&conn).await.expect("Failed to create table");

    let app_state = web::Data::new(AppState {
        db: Mutex::new(conn),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(ingest_data)
            .service(get_sensor_data)
            .service(get_sensor_data_by_field)
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}


#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, http::StatusCode};
    use serde_json::json;

    #[actix_rt::test]
    async fn test_ingest_and_get_data() {
        let conn = Connection::open_in_memory().expect("Failed to open in-memory database");
        create_table(&conn).await.expect("Failed to create table");

        let app_state = web::Data::new(AppState {
            db: Mutex::new(conn),
        });

        let app = test::init_service(
            App::new()
                .app_data(app_state.clone())
                .service(ingest_data)
                .service(get_sensor_data)
                .service(get_sensor_data_by_field),
        )
        .await;

        // Ingest data
        let payload = json!({
            "sensor_name": "Test Sensor",
            "field": "temperature",
            "value": "25.5",
            "type": "number"
        });

        let req = test::TestRequest::post()
            .uri("/ingest")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED); // Signature check will fail

        // Get data
        let req = test::TestRequest::get().uri("/data/Test%20Sensor").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND); // No data ingested
    }
}
