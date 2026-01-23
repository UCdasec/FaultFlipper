FROM ghcr.io/prefix-dev/pixi:latest AS install

WORKDIR /code
COPY pixi.toml .

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

RUN pixi install

# Create the shell-hook bash script to activate the environment
RUN pixi shell-hook > /shell-hook.sh

# extend the shell-hook script to run the command passed to the container
RUN echo 'exec "$@"' >> /shell-hook.sh

FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
	python3-pip \
	build-essential \
	qemu-user-static \
	gcc-arm-linux-gnueabi && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

COPY --from=install /shell-hook.sh /shell-hook.sh
RUN ulimit -c 0
RUN chmod 777 /shell-hook.sh
RUN pip3 install py-spy 

COPY --from=install /code/.pixi/envs/default /code/.pixi/envs/default

WORKDIR /code

# set the entrypoint to the shell-hook script (activate the environment and run the command)
# no more pixi needed in the prod container
ENTRYPOINT ["/bin/bash", "/shell-hook.sh"]
