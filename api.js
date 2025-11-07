const express = require('express');
const axios = require('axios');
const cors = require('cors');
const base64 = require('base64-js');
const jwt = require('jsonwebtoken');  // Added for JWT decoding
const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 3000;

// Cache for storing the access token
let pw_token = '';
let tokenExpiry = 0;

// Function to get or refresh the access token
async function getAccessToken() {
    const now = Date.now();
    // If we have a valid token, return it
    if (pw_token && tokenExpiry > now + 60000) { // 1 minute buffer
        return pw_token;
    }

    try {
        console.log('Fetching new access token...');
        const response = await axios.get('https://api-accesstoken.vercel.app/');
        
        if (response.data && response.data.access_token) {
            pw_token = response.data.access_token;
            // Parse the JWT to get expiry time (in seconds) and convert to milliseconds
            const decoded = jwt.decode(pw_token);
            if (decoded && decoded.exp) {
                tokenExpiry = decoded.exp * 1000; // Convert to milliseconds
            }
            console.log('Successfully fetched new access token');
            return pw_token;
        }
        throw new Error('Invalid token response');
    } catch (error) {
        console.error('Error fetching access token:', error.message);
        // If we have an expired token, clear it
        pw_token = '';
        tokenExpiry = 0;
        throw new Error('Failed to fetch access token');
    }
}

// Initialize the token when the server starts
let pw_token_initialized = getAccessToken().catch(err => {
    console.error('Failed to initialize access token:', err);
});

// Function to fetch stream info from the API
async function getStreamInfo(videoId, subjectId, batchId) {
    // Ensure we have a valid access token
    await pw_token_initialized; // Wait for initial token if still initializing
    const accessToken = await getAccessToken();
    
    const headers = {
        "Host": "studymeta.in",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not)A;Brand";v="8", "Chromium";v="138"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Sec-Ch-Ua-Mobile": "?0",
        "Accept": "*/*",
        "Origin": "https://www.studymeta.in/",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.studymeta.in/",
        "Priority": "u=1, i",
        "Authorization": `Bearer ${accessToken.replace(/^"|"$/g, '')}`,
        "Cookie": "accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2OTBkNjhlZDA5ODc0YTIxYTIzNDY5M2IiLCJuYW1lIjoiQXNoYSBLdW1hcmkiLCJ0ZWxlZ3JhbUlkIjpudWxsLCJQaG90b1VybCI6Imh0dHBzOi8vZDJicHM5cDFraXk0a2EuY2xvdWRmcm9udC5uZXQvNWIwOTE4OWY3Mjg1ODk0ZDkxMzBjY2QwLzMzNTFhZTg1LTNhYzgtNGRlZC05ZDE0LTk5NzNmZDI3MzA2NC5wbmciLCJpYXQiOjE3NjI0ODY1MTAsImV4cCI6MTc2Mzc4MjUxMH0.KeQI_a9MXNDvEMl29ADh3giHl_IxrLKQgpirTQ8QGNU; refreshToken=d0"
    };

    const params = {
        batchId: batchId,
        subjectId: subjectId,
        childId: videoId,
    };

    try {
        const response = await axios.get("https://www.powerstudy.site/api/media/get-video-url", {
            params: params,
            headers: headers
        });
        
        return response.data;
    } catch (error) {
        console.error("Error fetching stream info:", error.message);
        throw new Error("Failed to retrieve stream info");
    }
}

// Function to extract MPD URL from JWT in m3u8_url
function extractMpdUrl(m3u8Url) {
    try {
        // Extract JWT token from URL
        const jwtToken = m3u8Url.split('/')[4];
        
        // Decode JWT without verification
        const decoded = jwt.decode(jwtToken);
        
        // Extract components and construct MPD URL
        const videoUrl = decoded.video_url;
        const polParams = decoded.pol;
        
        // Remove any leading '?' if present
        const cleanPol = polParams.startsWith('?') ? polParams.substring(1) : polParams;
        
        return `${videoUrl}?${cleanPol}`;
    } catch (error) {
        console.error("Error extracting MPD URL:", error);
        throw new Error("Failed to extract MPD URL from JWT");
    }
}

// Fetch MPD and extract PSSH/KID
async function getPsshKid(mpdUrl) {
    let pssh = '', kid = '';
    for (let i = 0; i < 3; i++) {
        try {
            console.log(`Attempt ${i+1}: Fetching MPD from ${mpdUrl}`);
            const response = await axios.get(mpdUrl);
            const mpdRes = response.data;
            
            console.log(`Response status: ${response.status}, Content type: ${response.headers['content-type']}`);
            
            if (typeof mpdRes === 'string') {
                console.log(`MPD content length: ${mpdRes.length} characters`);
                
                // Extract PSSH with multiple patterns
                const psshPatterns = [
                    /<cenc:pssh>(.*?)<\/cenc:pssh>/,
                    /<ContentProtection schemeIdUri="urn:mpeg:dash:mp4protection:2011".*?default_KID="([^"]+)"/,
                    /<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"(?:.*?)<cenc:pssh>(.*?)<\/cenc:pssh>/,
                    /cenc:pssh=(.*?)[\s>]/
                ];
                
                for (const pattern of psshPatterns) {
                    const match = mpdRes.match(pattern);
                    if (match && match[1]) {
                        pssh = match[1].trim();
                        break;
                    }
                }
                
                // Extract KID with multiple patterns
                const kidPatterns = [
                    /default_KID="([^"]+)"/,
                    /content_KID="([^"]+)"/,
                    /KID="([^"]+)"/,
                    /key_id="([^"]+)"/
                ];
                
                for (const pattern of kidPatterns) {
                    const match = mpdRes.match(pattern);
                    if (match && match[1]) {
                        kid = match[1].replace(/-/g, '');
                        break;
                    }
                }
                
                // Log debug info
                console.log(`Found PSSH: ${pssh || 'None'}`);
                console.log(`Found KID: ${kid || 'None'}`);
                console.log(`PSSH pattern matches: ${mpdRes.match(/<cenc:pssh>/gi)?.length || 0}`);
                console.log(`KID pattern matches: ${mpdRes.match(/default_KID=/gi)?.length || 0}`);
            } else {
                console.log('Response data is not a string:', typeof mpdRes);
            }
            
            if (pssh && kid) break;
            
        } catch (error) {
            console.error(`Attempt ${i+1}: Error fetching MPD - ${error.message}`);
            if (error.response) {
                console.error(`HTTP Status: ${error.response.status}`);
                console.error(`Response data: ${JSON.stringify(error.response.data)}`);
            }
        }
    }
    return { pssh, kid };
}

// Encode string to UTF-16 hex
function encodeUtf16Hex(inputString) {
    let hexString = '';
    for (let i = 0; i < inputString.length; i++) {
        const hex = inputString.charCodeAt(i).toString(16).padStart(4, '0');
        hexString += hex;
    }
    return hexString;
}

// Generate OTP key
function getOtpKey(kid) {
    const xorBytes = [];
    for (let i = 0; i < kid.length; i++) {
        const charCode = kid.charCodeAt(i) ^ pw_token.charCodeAt(i % pw_token.length);
        xorBytes.push(charCode);
    }
    return base64.fromByteArray(Uint8Array.from(xorBytes));
}

// Decode key from OTP
function getKey(otp) {
    const decoded = base64.toByteArray(otp);
    let key = '';
    for (let j = 0; j < decoded.length; j++) {
        const charCode = decoded[j] ^ pw_token.charCodeAt(j % pw_token.length);
        key += String.fromCharCode(charCode);
    }
    return key;
}

// Fetch keys using KID
async function getKeys(kid) {
    const otpKey = getOtpKey(kid);
    const encodedHex = encodeUtf16Hex(otpKey);
    
    const headers = {
        "Host": "api.penpencil.xyz",
        "Content-Type": "application/json",
        "Authorization": `Bearer ${pw_token}`,
        "Client-Version": "11",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; PACM00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.98 Mobile Safari/537.36",
        "Client-Type": "WEB",
        "Accept-Encoding": "gzip",
    };
    
    const otpUrl = `https://api.penpencil.xyz/v1/videos/get-otp?key=${encodedHex}&isEncoded=true`;

    for (let i = 0; i < 3; i++) {
        try {
            const response = await axios.get(otpUrl, { headers });
            if (!response.data.data || !response.data.data.otp) {
                throw new Error('OTP not found in response');
            }
            
            const otp = response.data.data.otp;
            const decryptionKey = getKey(otp);
            return `${kid}:${decryptionKey}`;
        } catch (error) {
            console.error(`Attempt ${i+1}: Error fetching key - ${error.message}`);
        }
    }
    throw new Error('Failed to retrieve key after 3 attempts');
}

// Main function to get DRM keys from MPD URL
async function getDrmKeys(mpdUrl) {
    const { kid } = await getPsshKid(mpdUrl);
    if (!kid) {
        throw new Error('KID extraction failed - check the MPD URL');
    }
    
    const key = await getKeys(kid);
    return { mpdUrl, kid, key };
}

// New endpoint to handle video info (GET, query params)
// Get video URL data directly without making an HTTP request
async function getVideoUrlData(video_id, subject_id, batch_id) {
    if (!video_id || !subject_id || !batch_id) {
        return {
            success: false,
            error: 'Missing required parameters: video_id, subject_id, batch_id'
        };
    }

    try {
        const videoData = await getStreamInfo(video_id, subject_id, batch_id);

        if (videoData && videoData.success && videoData.data) {
            const { url, signedUrl, ...videoInfo } = videoData.data;
            const fullUrl = url + (signedUrl || '');
            
            return {
                success: true,
                directUrl: fullUrl,
                videoInfo: {
                    ...videoInfo,
                    fullUrl: fullUrl
                }
            };
        } else {
            return { success: false, error: 'Invalid response format from video URL API' };
        }
    } catch (error) {
        console.error('Error in getVideoUrlData:', error);
        return {
            success: false,
            error: error.message || 'Failed to fetch video URL',
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        };
    }
}

app.get('/getkeys-from-video-info', async (req, res) => {
    try {
        const { video_id, subject_id, batch_id } = req.query;
        
        if (!video_id || !subject_id || !batch_id) {
            return res.status(400).json({ 
                error: 'Parameters video_id, subject_id, and batch_id are required',
                parameters: ['video_id', 'subject_id', 'batch_id']
            });
        }
        
        console.log(`Fetching video URL for video_id: ${video_id}`);
        
        // Step 1: Get direct video URL data directly
        const videoResponse = await getVideoUrlData(video_id, subject_id, batch_id);
        
        if (!videoResponse.success || !videoResponse.directUrl) {
            throw new Error('Failed to fetch video URL: ' + (videoResponse.error || 'Unknown error'));
        }
        
        const mpdUrl = videoResponse.directUrl;
        console.log(`Retrieved MPD URL: ${mpdUrl}`);
        
        // Step 2: Get DRM keys
        const result = await getDrmKeys(mpdUrl);
        
        res.json({
            status: 'success',
            video_id,
            mpdUrl: result.mpdUrl,
            kid: result.kid,
            key: result.key,
            timestamp: new Date().toISOString(),
            videoInfo: videoResponse.videoInfo
        });
        
    } catch (error) {
        console.error('Video info endpoint error:', error.message);
        res.status(500).json({ 
            status: 'error',
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Existing endpoint for direct MPD URLs
app.post('/getkeys', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ 
                error: 'URL is required',
                usage: 'Send a POST request with JSON body: {"url": "your_mpd_url_here"}'
            });
        }
        
        console.log(`Processing request for MPD URL: ${url}`);
        
        // Extract KID from MPD
        const { kid } = await getPsshKid(url);
        if (!kid) {
            throw new Error('KID extraction failed - check the MPD URL');
        }
        
        console.log(`Extracted KID: ${kid}`);
        
        // Get decryption key
        const key = await getKeys(kid);
        
        res.json({
            status: 'success',
            mpdUrl: url,
            kid: kid,
            key: key,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('API Error:', error.message);
        res.status(500).json({ 
            status: 'error',
            message: error.message,
            solution: 'Check that the MPD URL is valid and the auth token is not expired'
        });
    }
});

// Homepage
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penpencil DRM Key Extraction API</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .container { background: #f5f5f5; padding: 20px; border-radius: 8px; }
                h1 { color: #333; }
                code { background: #eee; padding: 2px 5px; border-radius: 3px; }
                pre { background: #333; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }
                .endpoint { margin: 20px 0; padding: 15px; background: #eef; border-left: 4px solid #4477ff; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Penpencil DRM Key Extraction API</h1>
                <p>This API extracts DRM keys from Penpencil content.</p>
                
                <div class="endpoint">
                    <h2>Endpoint 1: Get keys from video info</h2>
                    <p>POST <code>/getkeys-from-video-info</code></p>
                    <p>Parameters:</p>
                    <pre>{
    "video_id": "66c029c57f6475deeef0d9d0",
    "subject_id": "5f9ff5bed4fc1f011595f1e0",
    "batch_id": "65dedbbd16156900189fdeec"
}</pre>
                </div>
                
                <div class="endpoint">
                    <h2>Endpoint 2: Convert DASH to MPD and get keys</h2>
                    <p>GET/POST <code>/convert-dash-to-mpd</code></p>
                    
                    <h3>Accepted URL patterns:</h3>
                    <ul>
                        <li><code>https://.../<uuid>/dash/240/2.mp4?...</code></li>
                        <li><code>https://.../<uuid>/dash/1.mp4?...</code></li>
                        <li><code>https://.../<uuid>/dash/audio/init.mp4?...</code></li>
                        <li><code>https://.../<uuid>/master.mpd?...</code> (used as-is)</li>
                    </ul>
                    
                    <h3>POST Method (Recommended):</h3>
                    <pre>{
    "url": "https://sec-prod-mediacdn.pw.live/7609c665-25b3-40b9-8ef2-b7ae5e0719c0/dash/240/2.mp4?URLPrefix=...&Expires=...&KeyName=...&Signature=..."
}</pre>
                    
                    <h3>GET Method:</h3>
                    <p>⚠️ For GET requests, the URL must be properly URL-encoded:</p>
                    <pre>https://your-api.com/convert-dash-to-mpd?url=https%3A//sec-prod-mediacdn.pw.live/7609c665-25b3-40b9-8ef2-b7ae5e0719c0/dash/240/2.mp4%3FURLPrefix%3D...%26Expires%3D...%26KeyName%3D...%26Signature%3D...</pre>
                    
                    <p><strong>Note:</strong> Use POST method to avoid URL encoding issues with complex URLs containing multiple query parameters.</p>
                </div>
                
                <div class="endpoint">
                    <h2>Endpoint 3: Get keys from MPD URL</h2>
                    <p>POST <code>/getkeys</code></p>
                    <p>Parameters:</p>
                    <pre>{
    "url": "https://sec-prod-mediacdn.pw.live/.../master.mpd?..."
}</pre>
                </div>
                
                <p class="success">API is running and ready to accept requests</p>
            </div>
        </body>
        </html>
    `);
});

// Endpoint to get direct video URL with signed token
app.get('/get-video-url', async (req, res) => {
    try {
        const { video_id, subject_id, batch_id } = req.query;
        
        if (!video_id || !subject_id || !batch_id) {
            return res.status(400).json({
                success: false,
                error: 'Missing required parameters: video_id, subject_id, batch_id'
            });
        }

        // Use existing getStreamInfo function to fetch video data
        const videoData = await getStreamInfo(video_id, subject_id, batch_id);

        if (videoData && videoData.success && videoData.data) {
            const { url, signedUrl, ...videoInfo } = videoData.data;
            const fullUrl = url + (signedUrl || '');
            
            return res.json({
                success: true,
                directUrl: fullUrl,
                videoInfo: {
                    ...videoInfo,
                    fullUrl: fullUrl
                }
            });
        } else {
            throw new Error('Invalid response format from video URL API');
        }
    } catch (error) {
        console.error('Error in /get-video-url:', error);
        res.status(500).json({
            success: false,
            error: error.message || 'Failed to fetch video URL',
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Helper: base64url encode a Buffer
function base64Url(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Route: GET or POST /get-clearkey-from-media-url
 * Accepts:
 *  - query param "url" (GET) OR JSON body { "url": "..." } (POST)
 *
 * Example request:
 *  GET /get-clearkey-from-media-url?url=https://sec-prod-mediacdn.pw.live/0337e5d2-728e-4c94-87cc-e13703cf639b/dash/audio/2.mp4?URLPrefix=...
 *
 * Response:
 * {
 *   status: "success",
 *   mpdUrl: "...",
 *   kid_hex: "...",
 *   key_raw: "...",           // string returned by your existing getKeys function (kid:key)
 *   clearkey: { keys: { "<kid_b64url>": "<key_b64url>" } }
 * }
 */
app.all('/get-clearkey-from-media-url', async (req, res) => {
    try {
        const inputUrl = (req.method === 'GET') ? req.query.url : (req.body && req.body.url);
        if (!inputUrl) {
            return res.status(400).json({ status: 'error', error: 'Missing "url" parameter (query or JSON body).' });
        }

        // Parse the URL
        let parsed;
        try {
            parsed = new URL(inputUrl);
        } catch (e) {
            return res.status(400).json({ status: 'error', error: 'Invalid URL provided.' });
        }

        // Try to find UUID segment in path (common in these URLs)
        // UUID regex: 8-4-4-4-12 (hex + dashes)
        const uuidMatch = parsed.pathname.match(/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\//);

        if (!uuidMatch) {
            return res.status(400).json({
                status: 'error',
                error: 'Could not find UUID segment in path to build master.mpd. Example path must contain the content-id UUID.'
            });
        }

        const uuid = uuidMatch[1]; // e.g. 0337e5d2-728e-4c94-87cc-e13703cf639b

        // Build master.mpd URL: origin + /<uuid>/master.mpd + original query string (if any)
        const mpdUrl = `${parsed.origin}/${uuid}/master.mpd${parsed.search || ''}`;

        console.log(`Constructed MPD URL from input: ${mpdUrl}`);

        // Use your existing getDrmKeys flow (which calls getPsshKid and getKeys)
        const drmResult = await getDrmKeys(mpdUrl); // returns { mpdUrl, kid, key }

        // drmResult.kid is returned by getPsshKid() as hex (you already strip dashes in getPsshKid)
        // drmResult.key is returned by getKeys() as "kid:decryptionKey" (string). If getKeys returns differently adapt accordingly.
        const returnedKey = drmResult.key || '';
        // If getKeys returned in form "kid:decryptionKey", split it.
        let kidHex = drmResult.kid || '';
        let decryptionKeyRaw = returnedKey.includes(':') ? returnedKey.split(':')[1] : returnedKey;

        // Build ClearKey JSON: convert kid hex -> base64url, convert decryptionKey (raw string) -> base64url
        // First convert kid hex (hex string) to Buffer
        let kidB64Url = '';
        try {
            const kidBuf = Buffer.from(kidHex, 'hex'); // assumes kidHex is hex (no dashes)
            kidB64Url = base64Url(kidBuf);
        } catch (e) {
            console.warn('Failed to convert kid hex to base64url:', e.message);
        }

        // Convert decryptionKeyRaw (binary string) into Buffer. Many of your helpers produce a raw byte-string.
        // We'll try a few options safely:
        let keyB64Url = '';
        try {
            // If decryptionKeyRaw looks like hex, convert hex
            if (/^[0-9a-fA-F]+$/.test(decryptionKeyRaw) && (decryptionKeyRaw.length % 2 === 0)) {
                keyB64Url = base64Url(Buffer.from(decryptionKeyRaw, 'hex'));
            } else {
                // otherwise assume it's a binary/string created by getKey() — use 'binary' encoding
                keyB64Url = base64Url(Buffer.from(decryptionKeyRaw, 'binary'));
            }
        } catch (e) {
            console.warn('Failed to convert decryption key to base64url:', e.message);
        }

        // ClearKey map (as expected by some players): keys: { "<kid_b64url>": "<key_b64url>" }
        const clearkeyObj = { keys: {} };
        if (kidB64Url && keyB64Url) clearkeyObj.keys[kidB64Url] = keyB64Url;

        // Return everything helpful
        return res.json({
            status: 'success',
            mpdUrl: drmResult.mpdUrl || mpdUrl,
            kid_hex: kidHex,
            key_raw: returnedKey,
            clearkey: clearkeyObj,
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error('Error in /get-clearkey-from-media-url:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', error: err.message || 'Internal error' });
    }
});

/**
 * Endpoint to convert DASH video URLs to master.mpd and get keys
 * Accepts URLs like: sec-prod-mediacdn.pw.live/0ad2248b-54ae-4a8a-8b54-c97936effbe8/dash/1.mp4?URLPrefix=...
 * Returns the same format as /getkeys-from-video-info endpoint
 */
app.all('/convert-dash-to-mpd', async (req, res) => {
    try {
        let inputUrl;
        
        if (req.method === 'GET') {
            // For GET requests, handle potential URL encoding issues
            inputUrl = req.query.url;
            
            // If multiple query parameters exist, reconstruct the full URL
            if (!inputUrl && Object.keys(req.query).length > 0) {
                // Check if the URL was split across multiple parameters
                const urlParts = [];
                const orderedParams = {};
                
                // Sort query parameters to maintain order
                Object.keys(req.query).forEach(key => {
                    const match = key.match(/url(\d*)/);
                    if (match) {
                        const index = match[1] ? parseInt(match[1]) : 0;
                        orderedParams[index] = req.query[key];
                    }
                });
                
                // If no url parameter found, try to extract from other parameters
                if (Object.keys(orderedParams).length === 0) {
                    // Try to find URL pattern in the query string
                    const queryString = req.url.split('?')[1];
                    if (queryString) {
                        inputUrl = queryString;
                    }
                }
            }
            
            // If inputUrl is null/undefined, try to parse raw query string
            if (!inputUrl) {
                const rawQuery = req.url.split('?')[1];
                if (rawQuery) {
                    // Try to decode the URL parameter properly
                    try {
                        const decoded = decodeURIComponent(rawQuery);
                        inputUrl = decoded;
                    } catch (e) {
                        console.log('URL decoding failed, using raw query');
                        inputUrl = rawQuery;
                    }
                }
            }
        } else {
            // For POST requests, use body directly
            inputUrl = req.body && req.body.url;
        }
        
        if (!inputUrl) {
            return res.status(400).json({ 
                status: 'error',
                error: 'Missing "url" parameter.',
                usage: {
                    GET: 'GET /convert-dash-to-mpd?url=https://sec-prod-mediacdn.pw.live/... (URL must be URL encoded)',
                    POST: 'POST /convert-dash-to-mpd with {"url": "https://sec-prod-mediacdn.pw.live/..."}'
                },
                received_query: req.query,
                received_body: req.body
            });
        }

        // Parse the URL
        let parsed;
        try {
            parsed = new URL(inputUrl);
        } catch (e) {
            return res.status(400).json({ 
                status: 'error',
                error: 'Invalid URL provided.',
                provided_url: inputUrl
            });
        }

        // Accept multiple patterns:
        // - /<uuid>/dash/<bitrate>/<n>.mp4 (e.g., /dash/240/2.mp4)
        // - /<uuid>/dash/audio/init.mp4
        // - /<uuid>/dash/<n>.mp4
        // - /<uuid>/master.mpd (already formed)
        // Extract UUID anywhere in the path first
        const uuidAnyMatch = parsed.pathname.match(/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\/|$)/);

        if (!uuidAnyMatch) {
            return res.status(400).json({
                status: 'error',
                error: 'Could not find UUID segment in the path.',
                provided_url: inputUrl,
                parsed_pathname: parsed.pathname
            });
        }

        const uuid = uuidAnyMatch[1];

        // If it's already master.mpd, use as-is
        let mpdUrl;
        if (/\/master\.mpd$/.test(parsed.pathname)) {
            mpdUrl = parsed.toString();
        } else {
            // Otherwise, construct master.mpd preserving the original query
            mpdUrl = `${parsed.origin}/${uuid}/master.mpd${parsed.search || ''}`;
        }

        console.log(`=== ${req.method} Request Debug ===`);
        console.log(`Original URL received: ${inputUrl}`);
        console.log(`URL length: ${inputUrl.length}`);
        console.log(`URL contains URLPrefix: ${inputUrl.includes('URLPrefix')}`);
        console.log(`URL contains Expires: ${inputUrl.includes('Expires')}`);

        // Use existing DRM keys extraction logic with improved error handling
        const { pssh, kid } = await getPsshKid(mpdUrl);
        console.log(`PSSH: ${pssh || 'Not found'}`);
        console.log(`KID: ${kid || 'Not found'}`);
        
        if (!kid) {
            // Try to fetch the MPD content directly to debug
            try {
                const testResponse = await axios.get(mpdUrl);
                console.log(`MPD Response Status: ${testResponse.status}`);
                console.log(`MPD Content Length: ${testResponse.data ? testResponse.data.length : 'No data'}`);
                
                // Check if it's actually MPD content
                if (testResponse.data && typeof testResponse.data === 'string') {
                    const isMpd = testResponse.data.includes('<MPD') || testResponse.data.includes('<?xml');
                    console.log(`Is MPD format: ${isMpd}`);
                    if (isMpd) {
                        // Extract all KID patterns found
                        const allKidMatches = testResponse.data.match(/default_KID="([^"]+)"/g) || [];
                        const allPsshMatches = testResponse.data.match(/<cenc:pssh>([^<]+)<\/cenc:pssh>/g) || [];
                        console.log(`All KID patterns found: ${allKidMatches.length}`);
                        console.log(`All KID matches:`, allKidMatches);
                        console.log(`All PSSH patterns found: ${allPsshMatches.length}`);
                        
                        if (allKidMatches.length === 0) {
                            throw new Error('No DRM KID found in MPD content - this may not be DRM protected content');
                        }
                    } else {
                        throw new Error('Response is not in MPD format - check URL construction');
                    }
                }
            } catch (debugError) {
                console.error(`Debug MPD fetch error: ${debugError.message}`);
            }
            
            throw new Error(`KID extraction failed - constructed MPD URL may be incorrect or content is not DRM protected. Debug info: ${pssh ? 'PSSH found but no KID' : 'No DRM elements found'}`);
        }

        console.log(`Extracted KID: ${kid}`);
        
        // Get decryption key
        const key = await getKeys(kid);

        res.json({
            status: 'success',
            originalUrl: inputUrl,
            mpdUrl: mpdUrl,
            kid: kid,
            key: key,
            timestamp: new Date().toISOString(),
            conversion: {
                uuid: uuid,
                origin: parsed.origin,
                queryString: parsed.search
            }
        });
        
    } catch (error) {
        console.error('DASH conversion endpoint error:', error.message);
        res.status(500).json({ 
            status: 'error',
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Endpoints:`);
    console.log(`- GET/POST http://localhost:${PORT}/convert-dash-to-mpd`);
    console.log(`- GET/POST http://localhost:${PORT}/getclearkey-from-media-url`);
    console.log(`- GET http://localhost:${PORT}/getkeys-from-video-info`);
    console.log(`- POST http://localhost:${PORT}/getkeys`);
    console.log(`- GET http://localhost:${PORT}/get-video-url`);
});
