# Imagen oficial y ligera de Node.js (LTS vigente; la 18 ya no recibe parches de seguridad)
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
# Solo dependencias de producción, reproducibles según package-lock.json
RUN npm ci --omit=dev
COPY . .
# Ejecutar como usuario sin privilegios (mínimo privilegio)
RUN mkdir -p logs && chown -R node:node /app
USER node
EXPOSE 3000
CMD ["npm", "start"]
