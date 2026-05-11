# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["Directory.Build.props", "."]
COPY ["Demo/Demo.csproj", "Demo/"]
COPY ["Src/Directory.Build.props", "Src/"]
COPY ["Src/Fido2.AspNet/Fido2.AspNet.csproj", "Src/Fido2.AspNet/"]
COPY ["Src/Fido2/Fido2.csproj", "Src/Fido2/"]
COPY ["Src/Fido2.Models/Fido2.Models.csproj", "Src/Fido2.Models/"]

RUN dotnet restore "Demo/Demo.csproj"

COPY . .
WORKDIR "/src/Demo"
RUN dotnet publish "Demo.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 2: Runtime — Ubuntu 25.10 (Questing) ships OpenSSL 3.5,
# which is required by .NET 10 for ML-KEM, ML-DSA and SLH-DSA.
FROM ubuntu:questing AS final

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libc6 \
        libgcc-s1 \
        libicu76 \
        libssl3t64 \
        libstdc++6 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Install .NET 10 ASP.NET Core runtime
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh \
    && bash dotnet-install.sh --runtime aspnetcore --channel 10.0 --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
    && rm dotnet-install.sh

WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_HTTP_PORTS=8080
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Demo.dll"]