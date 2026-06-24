from fastmcp import FastMCP
from supabase import create_client
import os

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

mcp = FastMCP("Estacion Meteorologica IoT - Diego Munoz")

@mcp.tool()
def get_latest_reading() -> dict:
    """Retorna la ultima lectura del sensor SHTC3 (temperatura y humedad) de la estacion meteorologica."""
    result = (
        supabase.table("sensor_readings")
        .select("*")
        .order("recorded_at", desc=True)
        .limit(1)
        .execute()
    )
    if result.data:
        return result.data[0]
    return {"error": "No hay lecturas disponibles"}

@mcp.tool()
def get_historical_data(limit: int = 10) -> list:
    """Retorna el historico de lecturas del sensor SHTC3. limit: numero de registros (max 50)."""
    result = (
        supabase.table("sensor_readings")
        .select("*")
        .order("recorded_at", desc=True)
        .limit(min(limit, 50))
        .execute()
    )
    return result.data

@mcp.tool()
def get_sensor_stats() -> dict:
    """Retorna estadisticas (min, max, promedio) de temperatura y humedad de las ultimas 50 lecturas."""
    result = (
        supabase.table("sensor_readings")
        .select("temperature, humidity, recorded_at")
        .order("recorded_at", desc=True)
        .limit(50)
        .execute()
    )
    if not result.data:
        return {"error": "Sin datos"}

    temps = [r["temperature"] for r in result.data if r.get("temperature") is not None]
    hums  = [r["humidity"]    for r in result.data if r.get("humidity")    is not None]

    return {
        "temperatura": {
            "min":      round(min(temps), 2),
            "max":      round(max(temps), 2),
            "promedio": round(sum(temps) / len(temps), 2),
        },
        "humedad": {
            "min":      round(min(hums), 2),
            "max":      round(max(hums), 2),
            "promedio": round(sum(hums) / len(hums), 2),
        },
        "total_lecturas": len(result.data),
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
