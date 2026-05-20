FROM continuumio/anaconda3

ARG UID=1000
ARG GID=1000
ARG DOCKER_GID=999

WORKDIR /app

COPY . .

RUN conda env create -f env.yaml

RUN echo "conda activate autobaxbuilder" >> ~/.bashrc
ENV PATH /opt/conda/envs/autobaxbuilder/bin:$PATH
ENV MPLCONFIGDIR=/tmp/matplotlib
ENV XDG_CACHE_HOME=/tmp/.cache
ENV DOCKER_BUILDKIT=1

RUN groupadd -g ${GID} appuser \
 && useradd -m -u ${UID} -g ${GID} appuser \
 && groupadd -g ${DOCKER_GID} docker \
 && usermod -aG docker appuser

USER appuser
