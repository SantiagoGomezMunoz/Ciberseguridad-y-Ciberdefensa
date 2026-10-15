# Usamos una imagen oficial y ligera de Node.js
FROM node:18-alpine

# Creamos la carpeta de trabajo dentro del contenedor
WORKDIR /app

# Copiamos primero los archivos de dependencias para aprovechar la caché de Docker
COPY package*.json ./

# Instalamos las dependencias del proyecto
RUN npm install

# Copiamos el resto del código fuente del proyecto
COPY . .

# Exponemos el puerto que usa tu aplicación (por lo general Express usa el 3000, 8080 o el que tengas en tu app.js/index.js)
EXPOSE 3000

# Comando para arrancar la aplicación
CMD ["npm", "start"]
