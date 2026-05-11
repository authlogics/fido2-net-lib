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

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
EXPOSE 8080
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Demo.dll"]