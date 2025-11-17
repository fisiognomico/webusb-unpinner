A docker to automate the installation of mitmproxy and webusb-unpinner,
launch from the top directory:
```bash
# Build the Docker image
docker-compose build

# Start the services
docker-compose up -d

# View logs
docker-compose logs -f

# Access the application
# WebUSB Unpinner: http://localhost:9000
# mitmproxy web interface: http://localhost:8081
```
