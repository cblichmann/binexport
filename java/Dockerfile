# Rebuild and upload with
#   podman build -t us-docker.pkg.dev/zynamics-build/docker-images/java:gradle-jdk17-ghidra11 .
#   podman push us-docker.pkg.dev/zynamics-build/docker-images/java:gradle-jdk17-ghidra11
#
# You may need to login to the Google cloud project first:
#   gcloud auth login
#   gcloud auth print-access-token | podman login -u oauth2accesstoken --password-stdin https://us-east1-docker.pkg.dev

# Example usage:
# podman run -it --rm -v $PWD:/home/gradle us-docker.pkg.dev/zynamics-build/docker-images/java:gradle-jdk17-ghidra11

# Use Gradle Ubuntu 22.04.4 LTS with OpenJDK17 as a base
FROM gradle:8.7-jdk17-jammy

ENV TZ=Europe/Zurich\
    DEBIAN_FRONTEND=noninteractive\
    GHIDRA_INSTALL_DIR=/opt/ghidra

RUN \
    apt-get update && \
    apt-get install -qy --no-install-recommends \
        gnupg \
    && \
    # Clean up to save space
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Install Ghidra
    [ "$(wget -qO - \
            https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip | \
            tee ghidra.zip | sha256sum | cut '-d ' -f1)" = \
        "2462a2d0ab11e30f9e907cd3b4aa6b48dd2642f325617e3d922c28e752be6761" ] && \
    unzip -q -d /opt ghidra.zip && \
    mv /opt/ghidra_*_PUBLIC /opt/ghidra && \
    rm ghidra.zip
