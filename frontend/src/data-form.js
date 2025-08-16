import { useState } from 'react';
import {
    Box,
    TextField,
    Button,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import axios from 'axios';

const endpointMapping = {
    'Notion': 'notion',
    'Airtable': 'airtable',
    'HubSpot': 'hubspot',
};

export const DataForm = ({ integrationType, credentials }) => {
    const [loadedData, setLoadedData] = useState(null);
    const [gridRows, setGridRows] = useState([]);
    const endpoint = endpointMapping[integrationType];

    const handleLoad = async () => {
        try {
            const formData = new FormData();
            formData.append('credentials', JSON.stringify(credentials));
            const response = await axios.post(`http://localhost:8000/integrations/${endpoint}/load`, formData);
            const data = response.data;
            setLoadedData(data);
            if (Array.isArray(data)) {
                const rows = data.map((d, idx) => ({ id: idx, ...d }));
                setGridRows(rows);
            } else {
                setGridRows([]);
            }
        } catch (e) {
            alert(e?.response?.data?.detail);
        }
    }

    return (
        <Box display='flex' justifyContent='center' alignItems='center' flexDirection='column' width='100%'>
            <Box display='flex' flexDirection='column' width='100%'>
                {Array.isArray(loadedData) && loadedData.length > 0 ? (
                    <Box sx={{ height: 400, width: '100%', mt:2 }}>
                        <DataGrid
                            rows={gridRows}
                            columns={[
                                { field: 'type', headerName: 'Type', width: 120 },
                                { field: 'name', headerName: 'Name', width: 220 },
                                { field: 'parent_path_or_name', headerName: 'Parent', width: 180 },
                            ]}
                            pageSize={10}
                        />
                    </Box>
                ) : (
                    <TextField
                        label="Loaded Data (raw)"
                        value={loadedData ? JSON.stringify(loadedData).slice(0,4000) : ''}
                        sx={{mt: 2}}
                        InputLabelProps={{ shrink: true }}
                        disabled
                        multiline
                        minRows={4}
                    />
                )}
                <Button
                    onClick={handleLoad}
                    sx={{mt: 2}}
                    variant='contained'
                >
                    Load Data
                </Button>
                <Button
                    onClick={() => { setLoadedData(null); setGridRows([]); }}
                    sx={{mt: 1}}
                    variant='contained'
                >
                    Clear Data
                </Button>
            </Box>
        </Box>
    );
}
