FROM ghcr.io/prefix-dev/pixi:latest AS install

# Force pixi to store the environment in a global location 
# so it doesn't get "buried" when we mount /code/FaultFlipper later
ENV PIXI_CACHE_DIR=/pixi_cache
RUN mkdir -p /pixi_cache

WORKDIR /code
COPY . .

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

# Move the environment outside of /code so it doesn't get overwritten by the mount
RUN pixi install
RUN pixi shell-hook > /shell-hook.sh && echo 'exec "$@"' >> /shell-hook.sh


FROM ubuntu:22.04 AS build

COPY --from=install /usr/local/bin/pixi /usr/bin/pixi
COPY --from=install /code/.pixi /code/.pixi
COPY --from=install /shell-hook.sh /shell-hook.sh

# Set the environment variable for matplotlib
ENV PATH="/usr/bin:/env/bin:${PATH}"
ENV MPLCONFIGDIR=/tmp/matplotlib_cache

# Install packages
RUN apt-get update && apt-get install -y \
	python3-pip build-essential qemu-user-static gcc-arm-linux-gnueabi && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

RUN ulimit -c 0
RUN chmod 777 /shell-hook.sh
RUN pip3 install py-spy 

WORKDIR /code/FaultFlipper

# set the entrypoint to the shell-hook script (activate the environment and run the command)
ENTRYPOINT ["/bin/bash", "/shell-hook.sh"]
