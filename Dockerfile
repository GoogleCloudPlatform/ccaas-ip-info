# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stage 1: Install production dependencies in an isolated build environment.
FROM node:20-bookworm-slim AS build
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Stage 2: Run in a Google-maintained, non-root distroless Node.js 20 image.
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /usr/src/app
COPY --from=build --chown=nonroot:nonroot /usr/src/app/node_modules ./node_modules
COPY --chown=nonroot:nonroot package.json index.js ./
COPY --chown=nonroot:nonroot public ./public

USER nonroot
CMD ["index.js"]
