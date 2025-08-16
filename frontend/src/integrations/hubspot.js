// hubspot.js
// Mirrors airtable & notion components; handles HubSpot OAuth popup & credential retrieval.

import { useState, useEffect } from 'react';
import { Box, Button, CircularProgress } from '@mui/material';
import axios from 'axios';

export const HubSpotIntegration = ({ user, org, integrationParams, setIntegrationParams }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);

  const handleConnectClick = async () => {
    try {
      setIsConnecting(true);
      const formData = new FormData();
      formData.append('user_id', user);
      formData.append('org_id', org);
      const { data: authURL } = await axios.post('http://localhost:8000/integrations/hubspot/authorize', formData);
      const popup = window.open(authURL, 'HubSpot Authorization', 'width=600,height=700');
      const pollTimer = window.setInterval(() => {
        if (popup?.closed !== false) {
          window.clearInterval(pollTimer);
          handleWindowClosed();
        }
      }, 250);
    } catch (e) {
      setIsConnecting(false);
      alert(e?.response?.data?.detail || 'HubSpot auth error');
    }
  };

  const handleWindowClosed = async () => {
    try {
      const formData = new FormData();
      formData.append('user_id', user);
      formData.append('org_id', org);
      const { data: credentials } = await axios.post('http://localhost:8000/integrations/hubspot/credentials', formData);
      if (credentials) {
        setIntegrationParams(prev => ({ ...prev, credentials, type: 'HubSpot' }));
        setIsConnected(true);
      }
    } catch (e) {
      alert(e?.response?.data?.detail || 'Could not retrieve HubSpot credentials');
    } finally {
      setIsConnecting(false);
    }
  };

  useEffect(() => {
    setIsConnected(!!integrationParams?.credentials && integrationParams?.type === 'HubSpot');
  }, [integrationParams]);

  return (
    <Box sx={{ mt: 2 }}>
      <Box display='flex' alignItems='center' justifyContent='center' sx={{ mt: 2 }}>
        <Button
          variant='contained'
          onClick={isConnected ? () => {} : handleConnectClick}
          color={isConnected ? 'success' : 'primary'}
          disabled={isConnecting}
          style={{
            pointerEvents: isConnected ? 'none' : 'auto',
            cursor: isConnected ? 'default' : 'pointer',
            opacity: isConnected ? 1 : undefined
          }}
        >
          {isConnected ? 'HubSpot Connected' : isConnecting ? <CircularProgress size={20} /> : 'Connect HubSpot'}
        </Button>
      </Box>
    </Box>
  );
};
