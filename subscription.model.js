import mongoose, { mongo } from 'mongoose'

const subscriptionSchema = new mongoose.Schema({ 
    subscriptionID: 
    { 
        type: String, 
        required: true, 
        unique: true
    },
},
{ 
    timestamps: true 
});

export default mongoose.model('Subscription', subscriptionSchema);