

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
export type Props = {
	login: string;
	name: string;
	email: string;
	accessToken: string;
};
