const startServer = () => {
    const PORT = process.env.PORT;
    if (!PORT) {
        console.error('PORT environment variable is not set.');
        process.exit(1);
    }

    const port = parseInt(PORT, 10);

    const server = app.listen(port, '0.0.0.0', (err) => {
        if (err) {
            if (err.code === 'EADDRINUSE') {
                console.error(`Error: Address in use. Please check if something is running on port ${port}.`);
            } else if (err.code === 'EACCES') {
                console.error(`Error: Permission denied. Unable to access port ${port}.`);
            } else {
                console.error('An error occurred while starting the server:', err);
            }
            process.exit(1);
        }
        console.log(`Server is running on http://0.0.0.0:${port}`);
    });
};