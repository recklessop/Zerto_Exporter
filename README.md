## About the app

This Python App will export Zerto API data from the new ZVM appliance in prometheus format. It has several different threads that each scrape different parts of the ZVM API. To visualize the data in Grafana you will need to scrape this app with Prometheus and then create dashboards using Grafana.


## Run Program

Login to the server where you want to run this exporter and clone the project:

```bash
  git clone https://github.com/recklessop/Zerto_Exporter.git
```

Go to the project directory:

```bash
  cd Zerto_Exporter
```

Build image and start the container:

```bash
  docker-compose up -d --build --force-recreate
```



## Add the exporter to Prometheus

Add this part at the end of the configuration of your Prometheus (prometheus.yaml):

```bash
  - job_name: python-exporter
    metrics_path: /metrics.txt
    static_configs:
      - targets: ['<IP-of-Node-Exporter-Server>:9999']
```


## Forked from

Huge shout out to hmdhszd for the framework that started this project. You can find his non-zerto version of a Python Prometheus Exporter [here.](
https://github.com/hmdhszd/Custom_Prometheus_Node_Exporter-in-Python)

