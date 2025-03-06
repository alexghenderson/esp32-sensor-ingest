use actix_web::{
    get, post, web, App, Error, HttpResponse, HttpServer,
};
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, env};

#[derive(Debug, Deserialize)]
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
     &IngestData,
) -> Result<(), rusqlite::Error> {
    let now = Utc::now().to_rfc3339();
    let conn = state.db.lock().unwrap();
    conn.execute(
        "INSERT INTO sensor_data (timestamp, sensor_name, field, value, type) VALUES (?, ?, ?, ?, ?)",
        params![&now, &data.sensor_name, &data.field, &data.value, &data.data_type],
    )?;
    Ok(())
}

#[post("/ingest")]
async fn ingest_data(
     web::Json<IngestData>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let data = data.into_inner();
    insert_sensor_data(&state, &data)
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
    .bind("127.0.0.1:8080")?
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
        assert_eq!(resp.status(), StatusCode::OK);

        // Get data
        let req = test::TestRequest::get().uri("/data/Test%20Sensor").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<SensorData> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].sensor_name, "Test Sensor");
        assert_eq!(body[0].field, "temperature");
        assert_eq!(body[0].value, "25.5");
        assert_eq!(body[0].data_type, "number");

        // Get data by field
        let req = test::TestRequest::get().uri("/data/Test%20Sensor/temperature").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<SensorData> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].sensor_name, "Test Sensor");
        assert_eq!(body[0].field, "temperature");
        assert_eq!(body[0].value, "25.5");
        assert_eq!(body[0].data_type, "number");
    }
}
