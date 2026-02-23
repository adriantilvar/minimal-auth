// 1xx: Informational
export const CONTINUE = { code: 100, name: "Continue" } as const;
export const SWITCHING_PROTOCOLS = { code: 101, name: "Switching Protocols" } as const;
export const PROCESSING = { code: 102, name: "Processing" } as const;
export const EARLY_HINTS = { code: 103, name: "Early Hints" } as const;

// 2xx: Success
export const OK = { code: 200, name: "OK" } as const;
export const CREATED = { code: 201, name: "Created" } as const;
export const ACCEPTED = { code: 202, name: "Accepted" } as const;
export const NON_AUTHORITATIVE_INFORMATION = { code: 203, name: "Non-Authoritative Information" } as const;
export const NO_CONTENT = { code: 204, name: "No Content" } as const;
export const RESET_CONTENT = { code: 205, name: "Reset Content" } as const;
export const PARTIAL_CONTENT = { code: 206, name: "Partial Content" } as const;
export const MULTI_STATUS = { code: 207, name: "Multi-Status" } as const;
export const ALREADY_REPORTED = { code: 208, name: "Already Reported" } as const;
export const IM_USED = { code: 226, name: "IM Used" } as const;

// 3xx: Redirection
export const MULTIPLE_CHOICES = { code: 300, name: "Multiple Choices" } as const;
export const MOVED_PERMANENTLY = { code: 301, name: "Moved Permanently" } as const;
export const FOUND = { code: 302, name: "Found" } as const;
export const SEE_OTHER = { code: 303, name: "See Other" } as const;
export const NOT_MODIFIED = { code: 304, name: "Not Modified" } as const;
export const USE_PROXY = { code: 305, name: "Use Proxy" } as const; // Deprecated but standard
export const TEMPORARY_REDIRECT = { code: 307, name: "Temporary Redirect" } as const;
export const PERMANENT_REDIRECT = { code: 308, name: "Permanent Redirect" } as const;

// 4xx: Client Error
export const BAD_REQUEST = { code: 400, name: "Bad Request" } as const;
export const UNAUTHORIZED = { code: 401, name: "Unauthorized" } as const;
export const PAYMENT_REQUIRED = { code: 402, name: "Payment Required" } as const;
export const FORBIDDEN = { code: 403, name: "Forbidden" } as const;
export const NOT_FOUND = { code: 404, name: "Not Found" } as const;
export const METHOD_NOT_ALLOWED = { code: 405, name: "Method Not Allowed" } as const;
export const NOT_ACCEPTABLE = { code: 406, name: "Not Acceptable" } as const;
export const PROXY_AUTHENTICATION_REQUIRED = { code: 407, name: "Proxy Authentication Required" } as const;
export const REQUEST_TIMEOUT = { code: 408, name: "Request Timeout" } as const;
export const CONFLICT = { code: 409, name: "Conflict" } as const;
export const GONE = { code: 410, name: "Gone" } as const;
export const LENGTH_REQUIRED = { code: 411, name: "Length Required" } as const;
export const PRECONDITION_FAILED = { code: 412, name: "Precondition Failed" } as const;
export const PAYLOAD_TOO_LARGE = { code: 413, name: "Payload Too Large" } as const;
export const URI_TOO_LONG = { code: 414, name: "URI Too Long" } as const;
export const UNSUPPORTED_MEDIA_TYPE = { code: 415, name: "Unsupported Media Type" } as const;
export const RANGE_NOT_SATISFIABLE = { code: 416, name: "Range Not Satisfiable" } as const;
export const EXPECTATION_FAILED = { code: 417, name: "Expectation Failed" } as const;
export const IM_A_TEAPOT = { code: 418, name: "I'm a teapot" } as const;
export const MISDIRECTED_REQUEST = { code: 421, name: "Misdirected Request" } as const;
export const UNPROCESSABLE_CONTENT = { code: 422, name: "Unprocessable Content" } as const;
export const LOCKED = { code: 423, name: "Locked" } as const;
export const FAILED_DEPENDENCY = { code: 424, name: "Failed Dependency" } as const;
export const TOO_EARLY = { code: 425, name: "Too Early" } as const;
export const UPGRADE_REQUIRED = { code: 426, name: "Upgrade Required" } as const;
export const PRECONDITION_REQUIRED = { code: 428, name: "Precondition Required" } as const;
export const TOO_MANY_REQUESTS = { code: 429, name: "Too Many Requests" } as const;
export const REQUEST_HEADER_FIELDS_TOO_LARGE = { code: 431, name: "Request Header Fields Too Large" } as const;
export const UNAVAILABLE_FOR_LEGAL_REASONS = { code: 451, name: "Unavailable For Legal Reasons" } as const;

// 5xx: Server Error
export const INTERNAL_SERVER_ERROR = { code: 500, name: "Internal Server Error" } as const;
export const NOT_IMPLEMENTED = { code: 501, name: "Not Implemented" } as const;
export const BAD_GATEWAY = { code: 502, name: "Bad Gateway" } as const;
export const SERVICE_UNAVAILABLE = { code: 503, name: "Service Unavailable" } as const;
export const GATEWAY_TIMEOUT = { code: 504, name: "Gateway Timeout" } as const;
export const HTTP_VERSION_NOT_SUPPORTED = { code: 505, name: "HTTP Version Not Supported" } as const;
export const VARIANT_ALSO_NEGOTIATES = { code: 506, name: "Variant Also Negotiates" } as const;
export const INSUFFICIENT_STORAGE = { code: 507, name: "Insufficient Storage" } as const;
export const LOOP_DETECTED = { code: 508, name: "Loop Detected" } as const;
export const NOT_EXTENDED = { code: 510, name: "Not Extended" } as const;
export const NETWORK_AUTHENTICATION_REQUIRED = { code: 511, name: "Network Authentication Required" } as const;
