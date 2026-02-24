export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      const backendUrl =
        "https://polaris-uru5.onrender.com" +
        url.pathname +
        url.search;

      return fetch(backendUrl, {
        method: request.method,
        headers: request.headers,
        body: request.method !== "GET" ? request.body : undefined,
      });
    }

    return fetch(request);
  },
};