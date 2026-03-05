# Architecture

```plain
┌─────────────┐      BLE       ┌──────────────┐      HTTPS      ┌─────────────┐
│   CareOtter │◄──────────────►│  App Patient │◄───────────────►│  API Cloud  │
│   (RPi+MAX) │  GATT Commands │   (Kotlin)   │  JWT/API Key    │  (Docker)   │
└──────┬──────┘                └──────────────┘                 └──────┬──────┘
       │                                                               │
       │ I2C                                                           │ HTTPS
       │                                                               │
┌──────▼──────┐                                                 ┌──────▼──────┐
│ MAX30102    │                                                 │  App Tutor  │
│ (HR/SpO2)   │                                                 │  (Kotlin)   │
└─────────────┘                                                 └─────────────┘
       │                                                               
       ▼  
Measurements -> Dosis simulation -> Alerts                                                             
```

```plain
labs/careotter/
├── etc/
│   ├── config/
│   │   └── bluetooth          # BLE configuration
│   ├── init.d/
│   │   └── careotter-daemon   # Init script
│   └── uci-defaults/
│       └── 99-careotter       # Initial setup post-flash
├── root/
│   └── careotter/
│       ├── core/
│       │   ├── __init__.py
│       │   ├── cardiac_monitor.py    # Lógica médica (alertas)
│       │   ├── data_store.py         # SQLite local
│       │   └── sensor_mock.py        # MAX30102 mock (ahora)
│       ├── api/
│       │   ├── __init__.py
│       │   ├── ble_gatt_server.py    # Servidor BLE
│       │   └── web_panel.py          # Panel CGI en OpenWRT
│       ├── config/
│       │   ├── thresholds.json       # Umbrales médicos
│       │   └── device.conf
│       └── www/
│           └── index.html            # Status simple
└── install.sh
```