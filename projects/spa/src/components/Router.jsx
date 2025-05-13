import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Landing from '../pages/Landing'
import TheZone from '../pages/TheZone'
import Tokens from '../pages/Tokens'

const routes = createBrowserRouter([
    {
        path: "/",
        element: <Landing />
    },
    {
        path: "/zone",
        element: <TheZone />
    },
    {
	path: "/tokens",
	element: <Tokens />
    }
]);

export default function AppRouter() {
    return <RouterProvider router={routes} />;
}

