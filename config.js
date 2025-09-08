(function(){
    let ApiBase;

    try {
        const isFile = location.origin.startsWith('file:');
        const isLocalhost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
        const currentPort = location.port || '4000';

        if (isFile) {
            ApiBase = `http://localhost:4000/api`;
        } else if (isLocalhost) {
            ApiBase = `http://localhost:${currentPort}/api`;
        } else {
            // production
            ApiBase = '/api';
        }
    } catch(_) {
        ApiBase = '/api';
    }

    window.API_BASE = ApiBase;
})();
