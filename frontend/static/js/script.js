function updateProviderFields() {
    const provider = document.getElementById('provider_type').value;
    const providerFields = document.getElementById('provider-fields');
    
    // Hide all fields first
    providerFields.innerHTML = '';
    
    // Common fields for most providers
    const commonFields = `
        <div class="form-group">
            <label for="bucket">Bucket Name:</label>
            <input type="text" class="form-control" id="bucket" name="bucket" required>
        </div>
    `;
    
    const s3Fields = `
        <div class="form-group">
            <label for="access_key">Access Key ID:</label>
            <input type="text" class="form-control" id="access_key" name="access_key" required>
        </div>
        <div class="form-group">
            <label for="secret_key">Secret Access Key:</label>
            <input type="password" class="form-control" id="secret_key" name="secret_key" required>
        </div>
        <div class="form-group">
            <label for="region">Region:</label>
            <select class="form-control" id="region" name="region" required>
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-east-2">US East (Ohio)</option>
                <option value="us-west-1">US West (N. California)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="eu-central-1">EU (Frankfurt)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
            </select>
        </div>
        ${commonFields}
    `;
    
    switch(provider) {
        case 'aws':
            providerFields.innerHTML = s3Fields;
            break;
            
        case 'wasabi':
            providerFields.innerHTML = `
                <div class="form-group">
                    <label for="access_key">Access Key ID:</label>
                    <input type="text" class="form-control" id="access_key" name="access_key" required>
                </div>
                <div class="form-group">
                    <label for="secret_key">Secret Access Key:</label>
                    <input type="password" class="form-control" id="secret_key" name="secret_key" required>
                </div>
                <div class="form-group">
                    <label for="region">Region:</label>
                    <select class="form-control" id="region" name="region" required>
                        <option value="us-east-1">US East 1 (N. Virginia)</option>
                        <option value="us-east-2">US East 2 (N. Virginia)</option>
                        <option value="us-central-1">US Central 1 (Texas)</option>
                        <option value="us-west-1">US West 1 (Oregon)</option>
                        <option value="eu-central-1">EU Central 1 (Amsterdam)</option>
                        <option value="eu-west-1">EU West 1 (London)</option>
                        <option value="ap-northeast-1">AP Northeast 1 (Tokyo)</option>
                    </select>
                </div>
                ${commonFields}
            `;
            break;
            
        case 'backblaze':
            providerFields.innerHTML = `
                <div class="form-group">
                    <label for="key_id">Application Key ID:</label>
                    <input type="text" class="form-control" id="key_id" name="key_id" required>
                </div>
                <div class="form-group">
                    <label for="application_key">Application Key:</label>
                    <input type="password" class="form-control" id="application_key" name="application_key" required>
                </div>
                <div class="form-group">
                    <label for="bucket_name">Bucket Name:</label>
                    <input type="text" class="form-control" id="bucket_name" name="bucket_name" required>
                    <small class="form-text text-muted">Must be a valid B2 bucket name (lowercase, no spaces)</small>
                </div>
            `;
            break;
            
        case 'gcs':
            providerFields.innerHTML = `
                <div class="form-group">
                    <label for="project_id">Project ID:</label>
                    <input type="text" class="form-control" id="project_id" name="project_id" required>
                </div>
                <div class="form-group">
                    <label for="bucket_name">Bucket Name:</label>
                    <input type="text" class="form-control" id="bucket_name" name="bucket_name" required>
                </div>
                <div class="form-group">
                    <label for="credentials_json">Service Account JSON:</label>
                    <textarea class="form-control" id="credentials_json" name="credentials_json" rows="10" required></textarea>
                </div>
            `;
            break;
            
        case 'digitalocean':
            providerFields.innerHTML = `
                <div class="form-group">
                    <label for="access_key">Access Key:</label>
                    <input type="text" class="form-control" id="access_key" name="access_key" required>
                </div>
                <div class="form-group">
                    <label for="secret_key">Secret Key:</label>
                    <input type="password" class="form-control" id="secret_key" name="secret_key" required>
                </div>
                <div class="form-group">
                    <label for="region">Region:</label>
                    <select class="form-control" id="region" name="region" required>
                        <option value="nyc3">New York (NYC3)</option>
                        <option value="ams3">Amsterdam (AMS3)</option>
                        <option value="sgp1">Singapore (SGP1)</option>
                        <option value="fra1">Frankfurt (FRA1)</option>
                        <option value="sfo3">San Francisco (SFO3)</option>
                    </select>
                </div>
                ${commonFields}
            `;
            break;
            
        case 'hetzner':
            providerFields.innerHTML = `
                <div class="form-group">
                    <label for="access_key">Access Key:</label>
                    <input type="text" class="form-control" id="access_key" name="access_key" required>
                </div>
                <div class="form-group">
                    <label for="secret_key">Secret Key:</label>
                    <input type="password" class="form-control" id="secret_key" name="secret_key" required>
                </div>
                <div class="form-group">
                    <label for="region">Region:</label>
                    <select class="form-control" id="region" name="region" required>
                        <option value="eu-central-1">EU Central (Germany)</option>
                        <option value="us-east-1">US East</option>
                        <option value="us-west-1">US West</option>
                    </select>
                </div>
                ${commonFields}
            `;
            break;
    }
} 