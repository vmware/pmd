FROM photon:4.0

RUN tdnf -y install git go build-essential shadow

RUN mkdir /build
COPY . /build
WORKDIR /build

RUN [ -d rpms ] && tdnf -y --repofrompath=tdnf,$(pwd)/rpms/ --repoid=tdnf install tdnf

RUN make build

RUN sed -i 's/systemctl daemon-reload/#systemctl daemon-reload/' Makefile
RUN make install

RUN useradd -M -s /usr/bin/nologin photon-mgmt

CMD /usr/bin/photon-mgmtd
