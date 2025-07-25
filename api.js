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
        "Host": "powerstudy.site",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not)A;Brand";v="8", "Chromium";v="138"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Sec-Ch-Ua-Mobile": "?0",
        "Accept": "*/*",
        "Origin": "https://www.powerstudy.site/",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.powerstudy.site/",
        "Priority": "u=1, i",
        "Authorization": `Bearer ${accessToken.replace(/^"|"$/g, '')}`,
        "Cookie": "accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODgzMWExMzljOGUzNmU2MDQxNzcxZDEiLCJuYW1lIjoiQXNoYSBLdW1hcmkiLCJ0ZWxlZ3JhbUlkIjpudWxsLCJQaG90b1VybCI6bnVsbCwiaWF0IjoxNzUzNDUyNzkzLCJleHAiOjE3NTQ3NDg3OTN9.gYwxrsUa_S6L6gnsTdUEl-XHUtb--qWBuXwl4b4PkmM; refreshToken=5b9191635f5c4dc73a7e7"
    };

    const params = {
        batchId: batchId,
        subjectId: subjectId,
        childId: videoId,
    };

    try {
        const response = await axios.get("https://www.powerstudy.site/api/get-video-url", {
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
            const response = await axios.get(mpdUrl);
            const mpdRes = response.data;
            
            // Extract PSSH
            const psshMatch = mpdRes.match(/<cenc:pssh>(.*?)<\/cenc:pssh>/);
            if (psshMatch) pssh = psshMatch[1];
            
            // Extract KID
            const kidMatch = mpdRes.match(/default_KID="([\S]+)"/);
            if (kidMatch) kid = kidMatch[1].replace(/-/g, '');
            
            if (pssh && kid) break;
        } catch (error) {
            console.error(`Attempt ${i+1}: Error fetching MPD - ${error.message}`);
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
                    <h2>Endpoint 2: Get keys from MPD URL</h2>
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

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Endpoints:`);
    console.log(`- POST http://localhost:${PORT}/getkeys-from-video-info`);
    console.log(`- POST http://localhost:${PORT}/getkeys`);
    console.log(`- GET http://localhost:${PORT}/get-video-url`);
});