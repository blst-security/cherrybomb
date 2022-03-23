
# Integrate with BLST using Winston

You can learn more about Winston in its [repository](https://github.com/winstonjs/winston).

## Get started

If you're already familiar with Winston, please skip to X 

### Install Winston
Using NPM:
```
npm install winston
```
Or using Yarn:
```
yarn add winston
```

### Create a logger 
In your Node.js server, import Winston like this:
```
const { createLogger, format, transports } =  require("winston");
```

Now create the logger, EXACTLY as we did:
```
const logger = createLogger({
	format: format.json(),
	transports: [
		new transports.Http({
			host: "TBD",
			path: "/TBD",
			ssl: true,
		}),
	],
});
```

Now, for each endpoint in which you want to send us logs from, add the following code:
```
logger.info(JSON.stringify({
	user_token: "USER_TOKEN_GOES_HERE",
	session_token: "SESSION_TOKEN_GOES_HERE",
	req_headers: request.headers,
	res_headers: response.getHeaders(),
	path: request.url,
	method: request.method,
	status: response.statusCode,
	req_payload: request.body,
	res_payload: "RETURNED_PAYLOAD_GOES_HERE",
	req_query: request.query,
}));
```

Please note the following things:
1. The fields and methods in this example should work as-is in express, but may require some changes in other frameworks and versions. Please refer to the docs of your framework for more details.
2. The user_token field should contain any kind of unique identifier of the user, i.e an access token,
3. The session_token field should contain any kind of unique identifier for the current session.
4. The res_payload field should contain the exact payload this current function invocation returns.

That's it, your logs should now be sent to our servers!
