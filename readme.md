# Bitcoin Address Matcher

This project is a Bitcoin address matcher that generates private keys and checks if they match any address from a given list. It uses Docker for consistent environment setup.

## Prerequisites

- Docker: Ensure Docker is installed and running on your system. You can download Docker from [Docker's official website](https://www.docker.com/get-started).

## Project Structure

/your-project-directory 
│ 
    ├── Dockerfile 
    ├── requirements.txt 
    ├── python_server.py 
    ├── data.txt 
    ├── logs/ 

# Logs directory to store process logs 
    └── results/ 

# Results directory to store matched addresses


## Building the Docker Image

1. Open a terminal and navigate to your project directory.

2. Build the Docker image using the following command:

    ```bash
    docker build -t btc-address-matcher .
    ```

    - `btc-address-matcher` is the name of the Docker image. You can choose a different name if you prefer.

## Running the Docker Container

1. Prepare the `data.txt` file containing the addresses you want to match.

2. Run the Docker container with the following command:

    ```bash
    docker run -it --rm \
      -v $(pwd)/logs:/app/logs \
      -v $(pwd)/results:/app/results \
      -v $(pwd)/data.txt:/app/data.txt \
      btc-address-matcher
    ```

    - `-v $(pwd)/logs:/app/logs`: Maps the `logs` directory on the host to `/app/logs` in the container. Logs will be saved here.
    - `-v $(pwd)/results:/app/results`: Maps the `results` directory on the host to `/app/results` in the container. Matching results will be saved here.
    - `-v $(pwd)/data.txt:/app/data.txt`: Maps the `data.txt` file on the host to `/app/data.txt` in the container. This file contains addresses to be matched.

## Viewing Results and Logs

- **Logs**: Check the `logs` directory on your host machine for process logs. Each process will have its own log file named `process_log_X.log`, where `X` is the process ID.

- **Results**: The `results` directory on your host machine will contain the `match.txt` file with addresses that matched and their associated private keys.

## Stopping the Container

The container will stop automatically once it has processed all the addresses or if a match is found. You can also stop it manually by pressing `Ctrl+C` in the terminal where the container is running.

## Troubleshooting

- **Container Fails to Start**: Ensure that Docker is properly installed and running. Check for errors in the Docker build or run commands.
- **File Not Found**: Verify that the `data.txt` file is correctly placed and mapped to the container. Ensure the directory paths are correct.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

