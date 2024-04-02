# citz-imb-ips-vrm
Information Privacy and Security's Vulnerability Risk Management tool

<br>




![vrm_app_architecture](https://github.com/bcgov/citz-imb-ips-vrm/assets/40187625/be6d6694-33e9-47a3-8073-25a309055289)


<br>

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites
This is an example of how to list things you need to use the software and how to install them.
* [python 3.9](https://www.python.org/downloads/) (Please download the version above 3.9)

### Create your `.env` file

Create a `.env` file in the root of your project and insert
your key/value pairs in the following format of `KEY=VALUE`:

If you need environment variable information for accessing JIRA, Postgres and PGAdmin, please contact [us](sarah.son@gov.bc.ca)
  
### Set up Docker and Docker Compose

To setup project specific docker containers, first make sure you have Docker Desktop installed on your machine. Next, run the following command.

```bash
docker-compose build
docker-compose up
```
This command will build the project DB, PGAdmin, Server containers. The name of all containers used within the VRM Integration project can be found in the docker-compose file found at the root level of this repository.
