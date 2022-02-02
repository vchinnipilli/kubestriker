FROM python:3.11-rc-slim as builder
RUN apt-get update -y \
&& apt-get clean -y
WORKDIR /kubestrike
RUN pip install --upgrade pip \
&& pip install prompt-toolkit==1.0.14 \
&& pip install kubestrike


FROM python:3.11-rc-slim
LABEL maintainer="vasant kumar chinnipilli"
COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=builder /kubestrike /kubestrike
WORKDIR /kubestrike
ENV PATH=/root/.local/bin:$PATH
CMD ["bash"]
