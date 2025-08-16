import React from 'react';
import { ThemeProvider, CssBaseline, Container, Box, Divider } from '@mui/material';
import { IntegrationForm } from './integration-form';
import { appTheme } from './theme';

function App() {
  return (
    <ThemeProvider theme={appTheme}>
      <CssBaseline />
      <Container maxWidth="lg" sx={{ py: 6 }}>
        <Box className="glass-card" sx={{ mb: 4 }}>
          <h1 style={{ margin: 0 }}>VectorShift Integrations</h1>
          <p className="muted" style={{ marginTop: '0.5rem' }}>Connect, authorize, and preview unified data objects from Airtable, Notion, and HubSpot.</p>
          <Divider sx={{ mt: 2, mb: 2, borderColor: 'rgba(255,255,255,0.1)' }} />
          <IntegrationForm />
        </Box>
      </Container>
    </ThemeProvider>
  );
}

export default App;
