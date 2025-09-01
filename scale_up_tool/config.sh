#!/bin/bash
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}" | tee ~/.ENV_SCALEUP
echo "GAUDINET_PATH=<PATH/TO/guadinet.json>" | tee -a ~/.ENV_SCALEUP
echo "SERVER_INTERNAL_CONNECTIVITY_PATH=<PATH/TO/server_internal_connectivity.csv>" | tee -a ~/.ENV_SCALEUP # This file is used to get the internal connectivity of the server (for example, take a look in the internal_data folder)