# Build context: repository root (docker build -f src/Mvv42.Auth/Dockerfile .)
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY global.json ./
COPY src/Mvv42.Auth/Mvv42.Auth.csproj src/Mvv42.Auth/
RUN dotnet restore src/Mvv42.Auth/Mvv42.Auth.csproj
COPY src/ src/
RUN dotnet publish src/Mvv42.Auth/Mvv42.Auth.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    Auth__KeysPath=/var/lib/mvv42-auth/keys
# Signing keys live in a host volume; the non-root "app" user (APP_UID=1654) must own it.
RUN mkdir -p /var/lib/mvv42-auth/keys && chown "$APP_UID" /var/lib/mvv42-auth/keys && chmod 700 /var/lib/mvv42-auth/keys
VOLUME /var/lib/mvv42-auth/keys
COPY --from=build /app/publish .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Mvv42.Auth.dll"]
