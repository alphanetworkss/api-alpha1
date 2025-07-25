const express = require('express');
const axios = require('axios');
const base64 = require('base64-js');
const { Buffer } = require('buffer');
const app = express();
app.use(express.json());

const PORT = 3000;
const pw_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NTMwMTg3MTcuMTc4LCJkYXRhIjp7Il9pZCI6IjY2ZTVhMTQxMzRiNjY5NmFlY2ViZmYzOCIsInVzZXJuYW1lIjoiOTkxMzExNTQ4NiIsImZpcnN0TmFtZSI6IkZhaXoiLCJvcmdhbml6YXRpb24iOnsiX2lkIjoiNWViMzkzZWU5NWZhYjc0NjhhNzlkMTg5Iiwid2Vic2l0ZSI6InBoeXNpY3N3YWxsYWguY29tIiwibmFtZSI6IlBoeXNpY3N3YWxsYWgifSwicm9sZXMiOlsiNWIyN2JkOTY1ODQyZjk1MGE3NzhjNmVmIl0sImNvdW50cnlHcm91cCI6IklOIiwidHlwZSI6IlVTRVIifSwiaWF0IjoxNzUyNDEzOTE3fQ.uvDZ3rLi-6CiigeQBOG9R6pIRb4uVcFyl0Y54taEkGk";

// Fetch MPD and extract PSSH/KID
async function getPsshKid(mpdUrl, headers = {}, cookies = {}) {
    let pssh = '', kid = '';
    for (let i = 0; i < 3; i++) {
        try {
            const response = await axios.get(mpdUrl, { headers, cookies });
            const mpdRes = response.data;
            const psshMatch = mpdRes.match(/<cenc:pssh>(.*?)<\/cenc:pssh>/);
            if (psshMatch) pssh = psshMatch[1];
            const kidMatch = mpdRes.match(/default_KID="([\S]+)"/);
            if (kidMatch) kid = kidMatch[1].replace(/-/g, '');
            if (pssh && kid) break;
        } catch (error) {
            console.error(`Attempt ${i+1}: Error fetching MPD`, error.message);
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
            const otp = response.data.data?.otp;
            if (!otp) throw new Error('OTP not found in response');
            const decryptionKey = getKey(otp);
            return `${kid}:${decryptionKey}`;
        } catch (error) {
            console.error(`Attempt ${i+1}: Error fetching key`, error.message);
        }
    }
    throw new Error('Failed to retrieve key after 3 attempts');
}

// Main function to get DRM keys
async function getDrmKeys(url) {
    const { kid } = await getPsshKid(url);
    if (!kid) throw new Error('KID extraction failed');
    const key = await getKeys(kid);
    return { mpdUrl: url, key };
}

// API endpoint
app.post('/getkeys', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL is required' });
        const result = await getDrmKeys(url);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /api/video/stream-info proxy endpoint
app.get('/api/proxy/stream-info', async (req, res) => {
    try {
        const {
            video_url = '',
            title = '',
            poster = '',
            video_type = '',
            video_id = '',
            subject_id = '',
            batch_id = ''
        } = req.query;

        const apiUrl = 'https://pw-api-75332756c41b.herokuapp.com/api/video/stream-info';
        const params = {
            video_url,
            title,
            poster,
            video_type,
            video_id,
            subject_id,
            batch_id
        };
        const headers = {
            'Host': 'pw-api-75332756c41b.herokuapp.com',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'Sec-Ch-Ua-Mobile': '?0',
            'Accept': '*/*',
            'Origin': 'https://pwthor.site',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://pwthor.site/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Priority': 'u=1, i',
            'Connection': 'keep-alive'
        };
        const { data } = await axios.get(apiUrl, { params, headers });
        if (!data.success || !data.m3u8_url) {
            return res.status(400).json({ error: 'Invalid response from upstream' });
        }
        // Extract JWT from m3u8_url
        const jwtMatch = data.m3u8_url.match(/\/([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)\//);
        if (!jwtMatch) {
            return res.status(400).json({ error: 'JWT not found in m3u8_url' });
        }
        const jwt = jwtMatch[1];
        // Decode JWT payload
        function decodeBase64Url(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length % 4) str += '=';
            try {
                return Buffer.from(str, 'base64').toString('utf8');
            } catch (e) {
                return null;
            }
        }
        let payloadRaw = decodeBase64Url(jwt.split('.')[1]);
        let payload;
        try {
            payload = JSON.parse(payloadRaw);
        } catch (e) {
            return res.status(400).json({ error: 'Failed to parse JWT payload', raw: payloadRaw });
        }
        if (!payload.video_url || !payload.pol) {
            return res.status(400).json({ error: 'video_url or pol missing in JWT payload', raw: payloadRaw });
        }
        const finalUrl = payload.video_url + payload.pol;
        res.json({ success: true, finalUrl, type: payload.type || null });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});