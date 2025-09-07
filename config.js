(function(){
    let resolvedApiBase = '/api';

    try {
        const isFile = location.origin.startsWith('file:');
        const isLocalhost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
        const currentPort = location.port || '4000';

        if (isFile) {
            resolvedApiBase = `http://localhost:4000/api`;
        } else if (isLocalhost) {
            resolvedApiBase = `http://localhost:${currentPort}/api`;
        } else {
            // production
            resolvedApiBase = '/api';
        }
    } catch(_) {}

    window.API_BASE = resolvedApiBase;
})();
