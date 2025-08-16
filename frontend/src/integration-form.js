import { useState } from 'react';
import { Box, Autocomplete, TextField, Paper, Chip } from '@mui/material';
import { AirtableIntegration } from './integrations/airtable';
import { NotionIntegration } from './integrations/notion';
import { HubSpotIntegration } from './integrations/hubspot';
import { DataForm } from './data-form';

const integrationMapping = {
    'Notion': NotionIntegration,
    'Airtable': AirtableIntegration,
    'HubSpot': HubSpotIntegration,
};

export const IntegrationForm = () => {
    const [integrationParams, setIntegrationParams] = useState({});
    const [user, setUser] = useState('TestUser');
    const [org, setOrg] = useState('TestOrg');
    const [currType, setCurrType] = useState(null);
    const CurrIntegration = integrationMapping[currType];

  return (
        <Box display='flex' justifyContent='center' alignItems='flex-start' flexDirection='column' sx={{ width: '100%' }}>
                <Box display='flex' flexDirection='column' sx={{ maxWidth: 340 }}>
        <TextField
            label="User"
            value={user}
            onChange={(e) => setUser(e.target.value)}
            sx={{mt: 2}}
        />
        <TextField
            label="Organization"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            sx={{mt: 2}}
        />
        <Autocomplete
            id="integration-type"
            options={Object.keys(integrationMapping)}
            sx={{ width: 300, mt: 2 }}
            renderInput={(params) => <TextField {...params} label="Integration Type" />}
            onChange={(e, value) => setCurrType(value)}
        />
        </Box>
                {currType && (
                    <Paper elevation={0} sx={{ mt: 3, p: 2, background: 'rgba(255,255,255,0.03)', width: '100%' }}>
                        <CurrIntegration user={user} org={org} integrationParams={integrationParams} setIntegrationParams={setIntegrationParams} />
                    </Paper>
                )}
                {integrationParams?.credentials && (
                    <Paper elevation={0} sx={{ mt: 3, p: 2, background: 'rgba(255,255,255,0.03)', width: '100%' }}>
                        <Box display='flex' alignItems='center' gap={1} mb={1}>
                            <Chip size='small' label={integrationParams.type + ' connected'} color='primary' />
                        </Box>
                        <DataForm integrationType={integrationParams?.type} credentials={integrationParams?.credentials} />
                    </Paper>
                )}
    </Box>
  );
}
