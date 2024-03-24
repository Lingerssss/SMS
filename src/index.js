import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';


function checkSignature(text, headers, githubSecretToken) {
  const hmac = createHmac('sha256', githubSecretToken);
  hmac.update(text);
  const expectedSignature = hmac.digest('hex');
  const actualSignature = headers.get('x-hub-signature-256');

  const trusted = Buffer.from(`sha256=${expectedSignature}`, 'ascii');
  const untrusted =  Buffer.from(actualSignature, 'ascii');

  return trusted.byteLength == untrusted.byteLength
    && timingSafeEqual(trusted, untrusted);
};


async function sendText(accountSid, authToken, message) {
	const endpoint = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
  
	const encoded = new URLSearchParams({
	  'To': '+8617635635721',
	  'From': '+15315354280',
	  'Body': message
	});
  
	const token = btoa(`${accountSid}:${authToken}`);
  
	const request = {
	  body: encoded,
	  method: 'POST',
	  headers: {
		'Authorization': `Basic ${token}`,
		'Content-Type': 'application/x-www-form-urlencoded',
	  }
	};
  
	const response = await fetch(endpoint, request);
	const result = await response.json();
  
	return Response.json(result);
  };

  export default {
	async fetch(request, env, ctx) {
		if(request.method !== 'POST') {
		  return new Response('Please send a POST request!');
		}
		try {
		  const rawBody = await request.text();
		  if (!checkSignature(rawBody, request.headers, env.GITHUB_SECRET_TOKEN)) {
			return new Response('Wrong password, try again', {status: 403});
		  }
	  
		  const action = request.headers.get('X-GitHub-Event');
		  const json = JSON.parse(rawBody);
		  const repoName = json.repository.full_name;
		  const senderName = json.sender.login;
	  
		  return await sendText(
			env.TWILIO_ACCOUNT_SID,
			env.TWILIO_AUTH_TOKEN,
			`${senderName} completed ${action} onto your repo ${repoName}`
		  );
		} catch (e) {
		  return new Response(`Error:  ${e}`);
		}
	  }
  };
  