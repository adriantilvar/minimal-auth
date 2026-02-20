export function containsFragment(uri: string): boolean {
	return uri.includes("#");
}

export function isString(n: unknown): n is string {
	return typeof n === "string";
}
